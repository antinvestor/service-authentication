CREATE INDEX IF NOT EXISTS idx_audit_entries_service_created_id
    ON audit_entries (service, created_at DESC, id DESC);
