-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License").

-- audit_entries is promoted to a TimescaleDB hypertable. The time-partition
-- column must be part of every UNIQUE/PRIMARY constraint, so replace the
-- BaseModel-default PK (id) with a composite (id, created_at). Audit rows
-- are immutable by policy, so the composite PK matches real write patterns.

ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_pkey;
ALTER TABLE audit_entries ADD PRIMARY KEY (id, created_at);
