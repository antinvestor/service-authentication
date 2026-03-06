-- Move logo_uri, post_logout_redirect_uris, token_endpoint_auth_method from
-- partition/client properties JSON to proper Client columns.
-- Also add parent_ref to link a client to its owning partition or service account.

ALTER TABLE clients ADD COLUMN IF NOT EXISTS logo_uri TEXT DEFAULT '';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB DEFAULT '{}';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(50) DEFAULT '';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS parent_ref VARCHAR(50) DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_clients_parent_ref ON clients (parent_ref) WHERE parent_ref != '';
