-- Opportunities SPA clients need resource audiences for matching (CV upload,
-- chat, onboarding), jobs API, billing, files, and notifications — not only
-- profile. Without these, Hydra issues access tokens with aud=/profile only
-- and opportunities-matching rejects them: "token has invalid audience" → 403.
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
  ('d9cvfix1prodmatch0001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/matching'),
  ('d9cvfix1prodjobs00001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/jobs'),
  ('d9cvfix1prodpay000001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/payment'),
  ('d9cvfix1prodfiles0001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/files'),
  ('d9cvfix1prodnotif0001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/notification'),
  -- dev: d7gi6ncpf2t7oh5akfr0
  ('d9cvfix1devprofile001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/profile'),
  ('d9cvfix1devmatch00001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/matching'),
  ('d9cvfix1devjobs000001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/jobs'),
  ('d9cvfix1devpay0000001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/payment'),
  ('d9cvfix1devfiles00001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/files'),
  ('d9cvfix1devnotif00001', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/notification')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('d7is2kspf2t7cl19qlp0', 'd7is2kspf2t7cl19qlpg');
