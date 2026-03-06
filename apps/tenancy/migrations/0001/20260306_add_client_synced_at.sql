-- Add synced_at column to clients table.
-- NULL means the client needs to be synced to Hydra.
-- A non-NULL timestamp means the client was last synced at that time.
ALTER TABLE clients ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_clients_synced_at ON clients (synced_at) WHERE synced_at IS NULL;
