CREATE INDEX IF NOT EXISTS idx_audit_entries_action_created_id
    ON audit_entries (action, created_at DESC, id DESC);
