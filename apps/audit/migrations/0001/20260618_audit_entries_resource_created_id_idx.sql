CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_created_id
    ON audit_entries (resource_type, resource_id, created_at DESC, id DESC);
