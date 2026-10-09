# Aithyrex Operations Runbook

## Status

This runbook describes operator procedures for the current repository. It is not proof that a production deployment exists.

## Provision a tenant

Tenant provisioning is operator-controlled; there is no self-service public provisioning endpoint.

1. Verify the Clerk organization ID and organization name in the Clerk dashboard through an authorized administrative session.
2. Configure the target environment's database URL, including TLS and non-default credentials. Do not commit production secrets.
3. From the repository root and the intended environment, run:

       python scripts/provision_tenant.py --clerk-org-id org_... --name "Organization Name"

4. Confirm the command reports the tenant UUID and the Free plan. The script does not accept a plan argument and cannot grant paid entitlements.
5. Verify that a member of the organization can authenticate with a valid Clerk session JWT and that another organization cannot access this tenant's records.

The command is idempotent for an already-active tenant. It refuses to silently reactivate an inactive tenant; follow the approved administrative recovery process instead.

## Deactivate a tenant

Use an authorized database administration process to set the tenant's active flag to false. Do not delete the tenant or its evidence records as a routine deactivation step. Record the operator, ticket, reason and timestamp in the organization's change/audit system.

## Production configuration gates

- Set APP_ENV to production or prod.
- Set a non-default APP_SECRET_KEY of at least 32 characters.
- Configure CLERK_JWT_KEY, CLERK_JWT_ISSUER and an explicit CLERK_AUTHORIZED_PARTIES list.
- Configure a TLS-protected remote DATABASE_URL and REDIS_URL.
- Configure explicit HTTPS ALLOWED_ORIGINS and ALLOWED_HOSTS.
- Configure ThreatFade and required downstream service credentials through the deployment secret manager.
- Verify database migrations, backups, restore procedures, TLS certificates, logs, alerts and rollback before exposing the API.

## Incident handling

- A degraded Aithyrex inspection is not a clean result; callers must stop protected downstream actions.
- Block-state or usage-accounting failures are fail-closed and may affect availability.
- A missing or malformed ThreatFade response is degraded.
- Do not paste raw prompts, completions, credentials, tokens or full URLs with query strings into tickets or logs.
- Preserve correlation IDs and evidence references. Treat a generated report or webhook response as distinct from proof of delivery or legal filing.

## Known operational blockers

- Service-to-service authentication for AURONTRA/Olvrix and other product integrations is not yet implemented; the current Clerk session-token mechanism is not a durable service credential.
- Durable event outbox, SIEM retry/idempotency and tenant-scoped live event publishing are not yet complete.
- Self-service tenant provisioning and automated organization lifecycle webhooks are not implemented.
- Production deployment and live integration status must be verified independently; this repository alone does not prove them.
