-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License").

CREATE TABLE IF NOT EXISTS external_identities (
    id varchar(50) NOT NULL,
    tenant_id varchar(50),
    partition_id varchar(50),
    access_id varchar(50),
    created_at timestamptz,
    modified_at timestamptz,
    created_by varchar(50),
    modified_by varchar(50),
    version bigint DEFAULT 0,
    deleted_at timestamptz,
    profile_id varchar(50) NOT NULL,
    provider varchar(32) NOT NULL,
    provider_subject varchar(255) NOT NULL,
    email_at_link varchar(255),
    email_verified boolean,
    last_seen_at timestamptz,
    properties jsonb,
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_external_identity_provider_subject
    ON external_identities (provider, provider_subject)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_external_identities_profile_id
    ON external_identities (profile_id);

CREATE INDEX IF NOT EXISTS idx_external_identities_email_at_link
    ON external_identities (email_at_link);

CREATE INDEX IF NOT EXISTS idx_external_identities_email_verified
    ON external_identities (email_verified);

CREATE INDEX IF NOT EXISTS idx_external_identities_last_seen_at
    ON external_identities (last_seen_at);
