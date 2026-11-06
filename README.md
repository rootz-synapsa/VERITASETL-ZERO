# VERITASETL ZERO

**Proof-Carrying Autonomous Supplier Data Repair**

A containment-first supplier data repair application built for the
Vultr × LabLab.ai Agent Rush Hackathon 2026 — Challenge 1: Blast Radius Zero.

## Product Objective

Turn supplier data repair into a governed, verifiable workflow.

Every execution must preserve a traceable chain:

Request → Authorization → Dispatch → Execution → Verification → Evidence

The worker must not authorize its own execution or certify its own output.

## Planned User Workflow

1. Upload a supplier CSV.
2. Inspect detected data issues.
3. Request a bounded repair.
4. Validate execution authority before dispatch.
5. Execute the repair in an isolated environment.
6. Independently verify the resulting data.
7. Download normalized data, exceptions, and an evidence receipt.

## Core Outputs

- `normalized.csv`
- `exceptions.csv`
- `job_summary.json`
- `evidence_receipt.json`

## Technology

- Python / FastAPI
- SQLite
- Docker-based worker isolation
- Vultr Serverless Inference

## Security Principles

- No secrets inside worker sandboxes.
- No network access from the worker.
- Least privilege and resource limits.
- Fail closed when authorization cannot be verified.
- Independent business verification.
- Evidence-linked execution results.

## Project Status

Initial repository foundation.

Runtime implementation and acceptance tests are not yet complete.
Features will be marked as implemented only after corresponding tests
and runtime evidence are available.

## Development

Setup and deployment instructions will be added as the implementation
progresses.
