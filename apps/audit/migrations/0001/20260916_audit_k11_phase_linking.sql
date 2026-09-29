-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License").

-- K11 (GFOS §10.4): request/outcome linking and degraded-mode marking.
-- The columns themselves are created by GORM auto-migration, which runs
-- before this file; this file adds the indexes the "asked, not done" query
-- and the degraded-entry review need.

-- Outcome lookup: the anti-join that finds REQUESTED entries nothing links
-- back to, and the forward lookup from a request to its outcome.
CREATE INDEX IF NOT EXISTS idx_audit_entries_outcome_of
    ON audit_entries (tenant_id, outcome_of_entry_id)
    WHERE outcome_of_entry_id IS NOT NULL AND outcome_of_entry_id <> '';

-- Requests pending an outcome, newest first.
CREATE INDEX IF NOT EXISTS idx_audit_entries_requested
    ON audit_entries (tenant_id, entry_id)
    WHERE phase = 'REQUESTED';

-- Entries written while AUDIT_DEGRADED was declared are reviewed as a set.
CREATE INDEX IF NOT EXISTS idx_audit_entries_degraded
    ON audit_entries (tenant_id, created_at DESC, id DESC)
    WHERE written_during_degradation;
