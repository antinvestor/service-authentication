-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License").

-- login_events is promoted to a TimescaleDB hypertable (see
-- apps/default/service/models/hypertables.go). TimescaleDB requires the
-- time-partition column to participate in every UNIQUE/PRIMARY constraint,
-- so we replace the BaseModel-default PK (id) with a composite (id, created_at).
-- Reads and writes through GORM continue to work because BeforeCreate sets
-- both columns and xid-generated ids remain globally unique.

ALTER TABLE login_events DROP CONSTRAINT IF EXISTS login_events_pkey;
ALTER TABLE login_events ADD PRIMARY KEY (id, created_at);
