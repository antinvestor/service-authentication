CREATE INDEX IF NOT EXISTS idx_audit_entries_created_id
    ON audit_entries (created_at DESC, id DESC);
