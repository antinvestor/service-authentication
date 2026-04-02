--- Copyright 2023-2026 Ant Investor Ltd
---
--- Licensed under the Apache License, Version 2.0 (the "License");
--- you may not use this file except in compliance with the License.
--- You may obtain a copy of the License at
---
---      http://www.apache.org/licenses/LICENSE-2.0
---
--- Unless required by applicable law or agreed to in writing, software
--- distributed under the License is distributed on an "AS IS" BASIS,
--- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--- See the License for the specific language governing permissions and
--- limitations under the License.


ALTER TABLE tenants
    ADD COLUMN searchable tsvector GENERATED ALWAYS AS ( jsonb_to_tsv(COALESCE(properties, '{}'::jsonb)) ) STORED;

CREATE INDEX idx_tenants_search_vector ON tenants USING GIN (searchable);

ALTER TABLE partitions
    ADD COLUMN searchable tsvector GENERATED ALWAYS AS ( jsonb_to_tsv(COALESCE(properties, '{}'::jsonb)) ) STORED;

CREATE INDEX idx_partitions_search_vector ON partitions USING GIN (searchable);