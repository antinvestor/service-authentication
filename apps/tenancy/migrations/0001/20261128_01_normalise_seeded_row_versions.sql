-- Seeded rows carry version NULL: the greenfield and later seed INSERTs pass
-- an explicit NULL for version, which overrides the column's DEFAULT 0.
-- Frame's BaseRepository.Update filters "id = ? AND version = ?" with the
-- loaded version (0 for a NULL scan) and NULL never compares equal, so every
-- update of a seeded tenant, partition, client or service account matched no
-- row. UpdatePartition then reported success without persisting anything.
--
-- 1 is the version BaseModel.BeforeCreate assigns to every row it creates.
--
-- The column stays nullable: BaseModel declares version without NOT NULL, so
-- GORM AutoMigrate would drop the constraint again on the next migrate run.
-- The tenancy business test suite asserts no BaseModel row is left NULL after
-- all migrations, which guards future seeds instead.

UPDATE public.tenants SET version = 1 WHERE version IS NULL;

UPDATE public.partitions SET version = 1 WHERE version IS NULL;

UPDATE public.partition_roles SET version = 1 WHERE version IS NULL;

UPDATE public.accesses SET version = 1 WHERE version IS NULL;

UPDATE public.access_roles SET version = 1 WHERE version IS NULL;

UPDATE public.pages SET version = 1 WHERE version IS NULL;

UPDATE public.clients SET version = 1 WHERE version IS NULL;

UPDATE public.service_accounts SET version = 1 WHERE version IS NULL;

UPDATE public.service_namespaces SET version = 1 WHERE version IS NULL;

UPDATE public.oauth_client_recipients SET version = 1 WHERE version IS NULL;

UPDATE public.service_account_authorization_policies SET version = 1 WHERE version IS NULL;

UPDATE public.service_account_authorization_grants SET version = 1 WHERE version IS NULL;

UPDATE public.service_account_authorization_permissions SET version = 1 WHERE version IS NULL;

UPDATE public.service_account_applied_tuples SET version = 1 WHERE version IS NULL;
