-- Allow multiple service accounts per (partition_id, profile_id).
-- Each service account gets a unique client_id (child partition) globally.
DROP INDEX IF EXISTS idx_sa_partition_profile;

CREATE INDEX IF NOT EXISTS idx_sa_partition_profile
    ON service_accounts (partition_id, profile_id)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sa_client_id
    ON service_accounts (client_id)
    WHERE deleted_at IS NULL;
