# Architecture

## Goal

Open Agentic Threat Defense detects agentic threat behavior by correlating
signals that are often handled separately:

- AI-agent and MCP-style tool calls;
- host process activity;
- outbound network flows;
- deception and canary hits;
- response and audit actions.

## MVP Components

### HTTP Service

`cmd/oadtd` starts a local HTTP service and serves both API endpoints and the
static dashboard.

### Domain Model

`internal/domain` defines the shared event, alert, asset, rule, and response
types.

### Store

`internal/store` keeps in-memory events, alerts, response actions, and risk
ranked assets. This is intentionally simple for the MVP and should become a
durable store in the alpha phase.

### Policy Engine

`internal/policy` evaluates single events for known defensive patterns:

- unapproved agent tool calls;
- potential secret exposure in agent context;
- unknown outbound egress;
- suspicious discovery process chains;
- canary or deception hits;
- suspicious local model runtime activity.

### Correlator

`internal/correlator` joins events over a time window and raises higher
confidence alerts when discovery, credential touch, agent tool use, and egress
appear on the same asset.

### Response Planner

`internal/response` creates dry-run response plans. The MVP does not execute
containment actions against real systems.

### Dashboard

`web/` provides an operational dashboard for assets, alerts, events, policies,
and dry-run response actions.

## Near-Term Production Shape

The next architecture step is to split collectors, policy evaluation, durable
storage, and response execution:

```mermaid
flowchart LR
  A["Collectors"] --> B["Ingest API"]
  B --> C["Event Store"]
  C --> D["Policy Engine"]
  C --> E["Correlator"]
  D --> F["Alert Store"]
  E --> F
  F --> G["Response Orchestrator"]
  G --> H["SIEM/EDR/Firewall/Ticketing"]
  F --> I["Dashboard"]
```

## Defensive Boundaries

The system should only simulate adversary behavior by emitting telemetry. It
must not include exploit code, self-propagation, credential theft, or destructive
actions.

