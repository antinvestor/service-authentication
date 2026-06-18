CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_created_id
    ON audit_entries (tenant_id, created_at DESC, id DESC);
