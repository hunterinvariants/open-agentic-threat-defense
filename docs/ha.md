# High Availability

OADTD is designed to run as multiple stateless replicas behind a reverse proxy
or load balancer.

## Deployment Shape

- one shared Postgres cluster
- two or more `oadtd` instances
- one reverse proxy or external load balancer
- one canonical `--public-url`
- one distinct `--instance-name` per node

## Runtime Rules

- sessions are signed and stateless
- all shared state lives in Postgres
- `/healthz` is process liveness
- `/readyz` is readiness against Postgres
- SSO callback URLs must match `--public-url`

## Rolling Update

1. drain one node from the load balancer
2. deploy the new release
3. restart the node
4. wait for `/readyz`
5. return the node to service
6. repeat for the next node

## Failover

If a node fails, remove it from the load balancer and keep serving from the
remaining nodes. If Postgres is unavailable, all replicas will fail readiness.
That is expected and prevents split-brain behavior.

## Example Systemd Model

Use `packaging/systemd/oadtd@.service` with one environment file per instance:

```text
/etc/oadtd/blue.env
/etc/oadtd/green.env
```

Each file should point at the same Postgres cluster, but can use a distinct
`OATD_PUBLIC_URL`, `OATD_ADDR`, and `OATD_INSTANCE_NAME`.
