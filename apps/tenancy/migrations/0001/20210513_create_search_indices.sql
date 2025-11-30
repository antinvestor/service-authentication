
ALTER TABLE tenants
    ADD COLUMN searchable tsvector GENERATED ALWAYS AS ( jsonb_to_tsv(COALESCE(properties, '{}'::jsonb)) ) STORED;

CREATE INDEX idx_tenants_search_vector ON tenants USING GIN (searchable);

ALTER TABLE partitions
    ADD COLUMN searchable tsvector GENERATED ALWAYS AS ( jsonb_to_tsv(COALESCE(properties, '{}'::jsonb)) ) STORED;

CREATE INDEX idx_partitions_search_vector ON partitions USING GIN (searchable);