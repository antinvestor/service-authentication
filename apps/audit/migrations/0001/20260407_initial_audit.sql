-- Audit Service initial schema
-- This migration creates composite indexes for common query patterns.
-- GORM auto-migration handles the table creation and single-column indexes.

-- Composite index for tenant-scoped time-range queries (most common pattern)
CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_created
    ON audit_entries (tenant_id, created_at DESC);

-- Composite index for "what did this user do" queries
CREATE INDEX IF NOT EXISTS idx_audit_entries_profile_created
    ON audit_entries (profile_id, created_at DESC);

-- Composite index for resource-specific audit trail
CREATE INDEX IF NOT EXISTS idx_audit_entries_resource
    ON audit_entries (resource_type, resource_id, created_at DESC);

-- Composite index for service-scoped queries
CREATE INDEX IF NOT EXISTS idx_audit_entries_service_created
    ON audit_entries (service, created_at DESC);

-- Composite index for chain verification (ordered by creation time within tenant)
CREATE INDEX IF NOT EXISTS idx_audit_entries_chain
    ON audit_entries (tenant_id, created_at ASC, id ASC);
