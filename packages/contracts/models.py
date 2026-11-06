"""Core contracts: proposals, context bindings, authority decisions, programs."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from enum import Enum


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


@dataclass(frozen=True)
class Program:
    name: str
    source: str

    @property
    def digest(self) -> str:
        return sha256_bytes(f"{self.name}\n{self.source}".encode("utf-8"))


@dataclass(frozen=True)
class WorkProposal:
    proposal_id: str
    actor_id: str
    project_id: str
    input_digest: str
    program_digest: str
    created_at: float


@dataclass(frozen=True)
class ContextBinding:
    project_id: str
    context_revision: int
    input_digest: str
    program_digest: str


@dataclass(frozen=True)
class AuthorityDecision:
    decision_id: str
    proposal_id: str
    decision: Decision
    reason: str
    actor_id: str
    project_id: str
    policy_version: str
    context_revision: int
    input_digest: str
    program_digest: str
    issued_at: float
    expires_at: float

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d
