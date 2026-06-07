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

## Operational Rule

Do not share a Postgres database between tenants if the policy requires
hard-isolated data retention, backup, or administrative access boundaries.
