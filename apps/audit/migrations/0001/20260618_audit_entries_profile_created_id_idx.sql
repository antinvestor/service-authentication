CREATE INDEX IF NOT EXISTS idx_audit_entries_profile_created_id
    ON audit_entries (profile_id, created_at DESC, id DESC);
