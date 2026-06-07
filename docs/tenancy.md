# Tenant Isolation

OADTD uses logical tenant isolation in the application and store layer. For
each request, the tenant is derived from the authenticated principal and the
read/write paths are scoped accordingly.

## Logical Isolation

- per-tenant reads for events, alerts, assets, actions, audits, and audit chain
- per-tenant writes for event ingestion, approval handling, gateway decisions,
  and action execution
- tenant-scoped RBAC and audit metadata

## Physical Isolation

If you need hard separation between tenants, deploy a separate OADTD instance
per tenant:

- distinct `--instance-name`
- distinct `--public-url`
- distinct Postgres database or cluster
- optional separate SSO application registration

That model gives you physical isolation at the deployment boundary instead of
sharing runtime state across tenants.

If you prefer a single control-plane process that provisions isolated stores on
first use, run with `--tenant-isolation-mode physical` and set one of:

- `--tenant-postgres-dsn-template`
- `--tenant-data-path-template`

The dashboard exposes a tenant admin panel through `GET /api/tenants` and
`POST /api/tenants`, plus per-tenant edit/delete through
`GET /api/tenants/{tenant}`, `PUT /api/tenants/{tenant}`, and
`DELETE /api/tenants/{tenant}`.

## Operational Rule

Do not share a Postgres database between tenants if the policy requires
hard-isolated data retention, backup, or administrative access boundaries.
