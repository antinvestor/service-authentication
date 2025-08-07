
ALTER TABLE tenants
    ADD COLUMN search_vector tsvector GENERATED ALWAYS AS ( jsonb_to_tsv(COALESCE(properties, '{}'::jsonb)) ) STORED;

CREATE INDEX idx_tenants_search_vector ON tenants USING GIN (search_vector);

ALTER TABLE partitions
    ADD COLUMN search_vector tsvector GENERATED ALWAYS AS ( jsonb_to_tsv(COALESCE(properties, '{}'::jsonb)) ) STORED;

CREATE INDEX idx_partitions_search_vector ON partitions USING GIN (search_vector);