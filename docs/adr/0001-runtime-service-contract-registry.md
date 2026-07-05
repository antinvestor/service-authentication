# ADR 0001: Runtime-owned service authorization contracts

- Status: Accepted
- Date: 2026-07-05

## Context

The authentication service issues OAuth credentials and materializes authorization policy, but it must not contain a compiled inventory of every platform service. A compiled permission or audience catalog makes every service launch require an authentication-service release and creates an unsafe ordering dependency between application and identity deployments.

## Decision

Each service owns its authorization contract in its protobuf `service_permissions` annotation and its Keto OPL namespace. Frame publishes the reflected manifest during every process start. The tenancy service stores the runtime registry and uses it to validate explicit service-account grants, human-role propagation, root authorization, and reconciliation.

The registration endpoint requires a verified service-account bearer token. The stable `service_account_id` claim comes from Hydra client metadata. Only a non-deleted internal service account in the root platform partition whose name exactly matches the manifest namespace may claim it. The first successful claim establishes immutable ownership by service-account ID and domain.

Manifest permissions and role bindings are additive-only. A changed manifest increments a generation. The generation is acknowledged only after synchronous root authorization succeeds and affected policy and partition reconciliation has been queued. Failed side effects leave the generation pending, so Frame's idempotent publisher retries it. Permission or role removal requires a future explicit, audited deprecation workflow; startup publication cannot remove live schema.

Authorization policies may reference only currently registered namespaces and explicit registered permissions. Policies that already exist while a required namespace is unavailable remain pending and grant nothing for that missing namespace. Keto remains the final authorization authority.

OAuth resource recipients are not checked against a compiled service catalog. They are accepted when they are canonical HTTPS child URLs of the configured platform audience base. This permits a new service audience without an authentication-service code change while preventing foreign-origin or malformed audiences.

## Service onboarding

1. An authorized platform administrator creates an internal service account in the root platform partition, named exactly as the service permission namespace. Its OAuth recipient list may include any canonical audience beneath the configured platform base.
2. The service defines its namespace, permissions, and standard-role bindings in protobuf and deploys the matching Keto OPL namespace.
3. The service starts with Frame permission registration enabled and an OAuth configuration capable of obtaining a tenancy-audience token.
4. Frame publishes the signed manifest. The registry binds ownership and triggers reconciliation.
5. Administrators may then create or update service-account policies that grant explicit permissions in the new namespace.

No authentication-service source, generated catalog, or migration change is required for steps 2 through 5.

## Consequences

- Service teams can add OAuth audiences and authorization permissions independently.
- A compromised service account cannot replace another service's registered namespace.
- Startup order is eventually consistent but fail-closed: unavailable registry or Keto schema dependencies delay grants rather than broadening access.
- Namespace ownership survives credential rotation because credentials rotate on the same service-account identity.
- Destructive permission and role evolution is intentionally unsupported until an explicit tuple-draining and OPL rollout protocol is implemented.
