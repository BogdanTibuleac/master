# Aegis Malware Robustness Platform — Technical Documentation

Document status: current implementation
Last reviewed: 31 August 2026

This directory is the technical documentation portal for the repository. It describes the
research pipeline, the hostile-content scanning runtime, the web application, and the
distributed adapters as they are implemented today.

The product has two related responsibilities:

1. Train and evaluate a static Windows PE malware classifier on the EMBER-v2 feature model.
2. Accept a quarantined PE file, extract static features without executing the file, score it,
   apply a policy, and return an immutable public result.

Static classification is a triage signal. It is not a guarantee that a file is safe, and it is
not a replacement for signature reputation, manual reverse engineering, or an isolated
behavioral sandbox.

## Implementation-status vocabulary

Every document uses the following meanings:

| Status | Meaning |
|---|---|
| **Implemented** | Present in the repository and exercised by automated tests or a build. |
| **Development-only** | Functional for local evaluation but not an adequate production control. |
| **Adapter available** | An implementation exists, but deployment composition or infrastructure is still required. |
| **Required before production** | A known control or integration is not complete. |

## Documentation map

| Document | Audience | Contents |
|---|---|---|
| [System overview](01-system-overview.md) | Product, engineering, security | Scope, capabilities, runtime profiles, and limitations |
| [Architecture](02-architecture.md) | Architects, senior engineers | Components, trust boundaries, state machine, and delivery semantics |
| [Backend design](03-backend-design.md) | Backend engineers | Package layering, services, repositories, and extension points |
| [Frontend design](04-frontend-design.md) | Frontend engineers | UI composition, scanner workflow, API integration, and UX states |
| [Scanner reference](05-hostile-content-scanner.md) | Security and operations | Exact checks, data sources, runtime modes, validation, and troubleshooting |
| [API reference](06-api-reference.md) | API consumers | Endpoints, headers, payloads, examples, and error behavior |
| [ML and data pipeline](07-ml-data-pipeline.md) | ML engineers, reviewers | EMBER acquisition, training, robustness evaluation, and hardening |
| [Configuration reference](08-configuration-reference.md) | Developers, operations | Environment variables, experiment files, and invalid combinations |
| [Local development](09-local-development.md) | Contributors | Setup, training, running, smoke tests, and common failures |
| [Deployment and operations](10-deployment-operations.md) | Platform and SRE | PostgreSQL, RabbitMQ, Azure Blob, extractor isolation, and runbooks |
| [Security and threat model](11-security-threat-model.md) | Security reviewers | Assets, threats, controls, residual risks, and production gates |
| [Testing and quality](12-testing-quality.md) | Maintainers, reviewers | Test coverage map, validation commands, quality gates, and gaps |
| [Data and artifact catalog](13-data-artifact-catalog.md) | Engineering, governance | Inputs, generated files, persistence, sensitivity, and retention gaps |
| [Known limitations and roadmap](14-known-limitations-roadmap.md) | Delivery leads, architects | Prioritized work required to evolve the MVP |
| [Rancher Desktop local stack](15-rancher-desktop-local-stack.md) | Developers, platform engineers | Compose services, host worker, disposable extractor, and troubleshooting |

## Quick paths

- To run the complete local application, start with [Local development](09-local-development.md).
- To integrate with the scanner API, use [API reference](06-api-reference.md).
- To understand why uploaded content is handled differently from ordinary files, read
  [Architecture](02-architecture.md) and [Security and threat model](11-security-threat-model.md).
- To operate PostgreSQL, RabbitMQ, or Azure Blob, use
  [Deployment and operations](10-deployment-operations.md).
- To understand exactly what can cause a suspicious verdict, use
  [Scanner reference](05-hostile-content-scanner.md).

## Sources of truth

When documentation and behavior differ, use this precedence order:

1. Database constraints and domain validation in `db/migrations/` and
   `src/malware_robustness/domain/`.
2. Runtime composition and settings in `src/malware_robustness/runtime_composition.py` and
   `src/malware_robustness/core/settings.py`.
3. HTTP route and schema definitions in `src/malware_robustness/routes/` and
   `src/malware_robustness/schemas/`.
4. This documentation.

Generated OpenAPI documentation is available from a running backend at
`http://127.0.0.1:8000/docs`. `POST /api/v1/scans` is a JSON metadata-only creation route; file
bytes are uploaded only through the scoped quarantine capability returned by that route.

## Repository boundaries

Committed source and configuration live in Git. Raw datasets, processed feature tables,
uploaded samples, scan metadata, immutable result objects, and model artifacts are generated
locally and ignored by Git. See [Data and artifact catalog](13-data-artifact-catalog.md) before
backing up, sharing, or deleting any generated directory.
