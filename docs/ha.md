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

- sessions are signed and stateless; the login lockout is shared via Postgres
- all durable shared state lives in Postgres
- `/healthz` is process liveness
- `/readyz` is readiness against Postgres
- SSO callback URLs must match `--public-url`

### HA caveats

- **Session revocation is per-instance.** Logout revokes a session via an
  in-memory denylist, so it takes effect only on the instance that served the
  request; the absolute session max-age still bounds every session globally. A
  shared revocation store would make logout cluster-wide.
- **Gateway backpressure is per-instance.** The in-flight limiter is a local
  semaphore (each replica protects itself), not a global cross-instance cap.

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

## Operational Helpers

- `scripts/ha-check.sh` validates readiness for all configured instances.
- `scripts/ha-rollout.sh` restarts instances one by one and waits for
  `/readyz` before moving to the next node.

Example:

```bash
sudo OATD_HA_INSTANCES=blue,green scripts/ha-check.sh
sudo OATD_HA_INSTANCES=blue,green scripts/ha-rollout.sh
```
