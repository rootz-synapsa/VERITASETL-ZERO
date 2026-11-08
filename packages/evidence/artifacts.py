"""Job artifact writer: persists worker outputs as files so verification reads disk, not worker memory."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ARTIFACT_NAMES = ("normalized.csv", "exceptions.csv", "job_summary.json")


def write_job_artifacts(output, out_dir) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    output = output if isinstance(output, dict) else {}
    payloads = {}
    if isinstance(output.get("normalized_csv"), str):
        payloads["normalized.csv"] = output["normalized_csv"]
    if isinstance(output.get("exceptions_csv"), str):
        payloads["exceptions.csv"] = output["exceptions_csv"]
    if isinstance(output.get("job_summary"), dict):
        payloads["job_summary.json"] = json.dumps(output["job_summary"], indent=2, sort_keys=True) + "\n"
    hashes = {}
    for name, text in payloads.items():
        data = text.encode("utf-8")
        (out / name).write_bytes(data)
        hashes[name] = "sha256:" + hashlib.sha256(data).hexdigest()
    return hashes
