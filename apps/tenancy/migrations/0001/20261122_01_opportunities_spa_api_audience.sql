-- Opportunities SPA clients need the opportunities api audience: the public
-- POST /opportunities/{slug}/flag route verifies the user JWT and requires
-- aud=https://api.stawi.org/opportunities. The SPA already carries profile,
-- matching, jobs, payment, files, notification and ats audiences
-- (20260714_01_opportunities_spa_audiences.sql, 20260812_02_service_ats.sql)
-- but not this one, so every flag would be rejected (403).
--
-- Applies to:
--   Stawi Opportunities Web         d7is2kspf2t7cl19qlp0 (prod)
--   Stawi Opportunities Development d7is2kspf2t7cl19qlpg (dev)
--
-- Tenancy must re-sync clients to Hydra after this (synced_at cleared).

INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  -- prod: d7gi6lkpf2t67dlsqrgg
  ('dc1ekqjfukklf995qpe0', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/opportunities'),
  -- dev: d7gi6ncpf2t7oh5akfr0
  ('dc1ekqjfukklf995qpeg', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/opportunities')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('d7is2kspf2t7cl19qlp0', 'd7is2kspf2t7cl19qlpg');
