-- Copyright 2023-2026 Ant Investor Ltd
-- Cleanup: remove orphan service-account seeds (no corresponding
-- HelmRelease in stawi.org/deployment.manifests) and the two
-- `trustage-{formstore,queuestore}` rows whose client_id never
-- matched their actual release names (`operations-formstore` and
-- `operations-queuestore`).
--
-- The orphan seed files have been deleted from this directory; this
-- migration cleans existing clusters that already applied them.
-- `operations-{formstore,queuestore}` seeds with fresh xids ship in
-- the sibling `20260420_service_operations_*.sql` files.
--
-- Idempotent — DELETE-by-id is a no-op on rows that don't exist.
--
-- Operator follow-up: delete the now-orphaned Hydra OAuth2 clients
-- (the seed migrations registered them, but no pod authenticates
-- as them any more):
--
--   for c in foundry gitvault service-fintech-identity \
--            service-fintech-loans service-profile-dek \
--            stawi-jobs-api stawi-jobs-candidates \
--            stawi-jobs-crawler stawi-jobs-scheduler \
--            trustage-formstore trustage-queuestore; do
--     curl -X DELETE "$HYDRA_ADMIN/admin/clients/$c"
--   done

-- foundry
DELETE FROM clients         WHERE id = 'c2f4j7au6s7f91uqnphg';
DELETE FROM service_accounts WHERE id = 'c2f4j7au6s7f91uqnpig';

-- gitvault
DELETE FROM clients         WHERE id = 'c2f4j7au6s7f91uqnpjg';
DELETE FROM service_accounts WHERE id = 'c2f4j7au6s7f91uqnpkg';

-- service-fintech-identity
DELETE FROM clients         WHERE id = 'd86tt34pf2tddudk9pgg';
DELETE FROM service_accounts WHERE id = 'd86tt34pf2tddudk9ph0';

-- service-fintech-loans
DELETE FROM clients         WHERE id = 'd86tt34pf2tddudk9pi0';
DELETE FROM service_accounts WHERE id = 'd86tt34pf2tddudk9pig';

-- service-profile-dek
DELETE FROM clients         WHERE id = 'd86tt34pf2tddudk9pjg';
DELETE FROM service_accounts WHERE id = 'd86tt34pf2tddudk9pk0';

-- stawi-jobs-api
DELETE FROM clients         WHERE id = 'c2f4j7au6s7f91uqnqhg';
DELETE FROM service_accounts WHERE id = 'c2f4j7au6s7f91uqnqig';

-- stawi-jobs-candidates
DELETE FROM clients         WHERE id = 'c2f4j7au6s7f91uqnqdg';
DELETE FROM service_accounts WHERE id = 'c2f4j7au6s7f91uqnqeg';

-- stawi-jobs-crawler
DELETE FROM clients         WHERE id = 'c2f4j7au6s7f91uqnqfg';
DELETE FROM service_accounts WHERE id = 'c2f4j7au6s7f91uqnqgg';

-- stawi-jobs-scheduler
DELETE FROM clients         WHERE id = 'c2f4j7au6s7f91uqnqjg';
DELETE FROM service_accounts WHERE id = 'c2f4j7au6s7f91uqnqkg';

-- trustage-formstore (replaced by operations-formstore)
DELETE FROM clients         WHERE id = 'd86tt34pf2tddudk9psg';
DELETE FROM service_accounts WHERE id = 'd86tt34pf2tddudk9pt0';

-- trustage-queuestore (replaced by operations-queuestore)
DELETE FROM clients         WHERE id = 'd86tt34pf2tddudk9pu0';
DELETE FROM service_accounts WHERE id = 'd86tt34pf2tddudk9pug';
