CREATE INDEX IF NOT EXISTS idx_audit_entries_target_profile_created_id
    ON audit_entries (target_profile_id, created_at DESC, id DESC);
