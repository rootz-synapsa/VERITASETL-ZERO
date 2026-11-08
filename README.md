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

Evidence-backed P0 vertical slice completed on the tested Vultr VM.

Verified gates currently included in the public evidence index:

- G1 Vultr Serverless Inference
- RR-AT-01 through RR-AT-04: pre-execution denial, revalidation, bypass protection, and replay protection
- EA-02/EA-03: tested Docker containment and sandbox lifecycle
- EA-04: independent business verification and false-completion rejection

The Judge Mode dashboard presents tested evidence and supplier-repair outputs as a verified fixture. A gate is not represented as PASS unless its corresponding runtime evidence is indexed and secret-scanned.

RR-AT-05, RR-AT-06, and EA-05 must remain explicitly pending unless their corresponding runtime evidence is present.

## Tested Claims and Limitations

The evidence package supports the tested behaviors above on the recorded Vultr VM. It does not claim that Docker prevents every possible escape, that SHA-256 makes evidence universally immutable, or that untested failure modes are impossible.

The dashboard is an evidence presentation view. It should not be described as a live upload endpoint unless a live upload route is separately deployed and tested.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000

Open http://127.0.0.1:8000/ for the Judge Mode evidence dashboard.


Setup and deployment instructions will be added as the implementation
progresses.
