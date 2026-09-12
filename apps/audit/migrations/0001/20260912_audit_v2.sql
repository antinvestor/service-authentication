-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License").

-- Audit v2: per-tenant sequence, chain heads, immutability triggers.
-- Columns and new tables are created by GORM auto-migration, which runs
-- before this file. This file adds the constraints auto-migration cannot
-- express.

-- 1. Greenfield: rows written by the pre-v2 service carry no seq, key id
--    or canonical hash and are not part of the chain. They are discarded;
--    the chain starts at seq 1 for every tenant.
TRUNCATE TABLE audit_entries;

-- 2. Hash columns must never be blank-padded (char(n) pads, breaking the
--    signed pre-image); enforce varchar regardless of how they were created.
ALTER TABLE audit_entries ALTER COLUMN payload_hash TYPE varchar(64);
ALTER TABLE audit_entries ALTER COLUMN authorization_hash TYPE varchar(64);
ALTER TABLE audit_entries ALTER COLUMN policy_hash TYPE varchar(64);

-- 3. Storage-level fork guard and chain-walk index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_entries_tenant_seq
    ON audit_entries (tenant_id, seq);

-- 4. Partial indexes for the evidence join keys.
CREATE INDEX IF NOT EXISTS idx_audit_entries_intent
    ON audit_entries (intent_id) WHERE intent_id IS NOT NULL AND intent_id <> '';
CREATE INDEX IF NOT EXISTS idx_audit_entries_correlation
    ON audit_entries (correlation_id) WHERE correlation_id IS NOT NULL AND correlation_id <> '';
CREATE INDEX IF NOT EXISTS idx_audit_entries_event
    ON audit_entries (event_id) WHERE event_id IS NOT NULL AND event_id <> '';

-- 5. Intake: idempotency key and drain scan. Checkpoints: one per position.
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_intake_dedupe
    ON audit_intake (tenant_id, service, entry_id);
CREATE INDEX IF NOT EXISTS idx_audit_intake_accepted
    ON audit_intake (tenant_id, received_at, id) WHERE state = 'ACCEPTED';
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_checkpoints_tenant_seq
    ON audit_checkpoints (tenant_id, seq);

-- 6. The legacy chain-walk index is superseded by seq.
DROP INDEX IF EXISTS idx_audit_entries_chain;

-- 7. Immutability. Migration and runtime share one database role in the
--    deployment, so a role-level REVOKE cannot distinguish them; triggers
--    enforce append-only semantics regardless of role. Soft deletes
--    (UPDATE deleted_at) are blocked as well.
CREATE OR REPLACE FUNCTION audit_raise_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit: % on % is not permitted (append-only)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_entries_immutable ON audit_entries;
CREATE TRIGGER audit_entries_immutable
    BEFORE UPDATE OR DELETE ON audit_entries
    FOR EACH ROW EXECUTE FUNCTION audit_raise_immutable();

DROP TRIGGER IF EXISTS audit_checkpoints_immutable ON audit_checkpoints;
CREATE TRIGGER audit_checkpoints_immutable
    BEFORE UPDATE OR DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_raise_immutable();

-- Signing keys: no DELETE; UPDATE may only set retired_at once.
CREATE OR REPLACE FUNCTION audit_signing_keys_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit: DELETE on audit_signing_keys is not permitted'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.key_id <> OLD.key_id OR NEW.public_key <> OLD.public_key
       OR NEW.algorithm <> OLD.algorithm OR NEW.valid_from <> OLD.valid_from
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
       OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
        RAISE EXCEPTION 'audit: only retired_at may be set on audit_signing_keys, once'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_signing_keys_guard ON audit_signing_keys;
CREATE TRIGGER audit_signing_keys_guard
    BEFORE UPDATE OR DELETE ON audit_signing_keys
    FOR EACH ROW EXECUTE FUNCTION audit_signing_keys_guard();
