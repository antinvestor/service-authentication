CREATE INDEX IF NOT EXISTS idx_audit_entries_device_created_id
    ON audit_entries (device_id, created_at DESC, id DESC);
