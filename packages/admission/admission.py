"""WorkerAdmission: attempt-bound, digest-bound, short-lived, single-use authorization."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import NoReturn

_REQUIRED = ("aid", "did", "in", "pg", "exp", "nonce")


class AdmissionDenied(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class _IssuerCapability:
    __slots__ = ("_id",)

    def __init__(self):
        self._id = secrets.token_hex(8)


@dataclass(frozen=True)
class AdmissionTicket:
    ticket_id: str
    attempt_id: str
    decision_id: str
    input_digest: str
    program_digest: str
    admitted_at: float


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)


class WorkerAdmission:
    def __init__(self, db_path: str, token_ttl_s: float = 30.0):
        self._key = secrets.token_bytes(32)
        self._cap = _IssuerCapability()
        self._cap_claimed = False
        self._ttl = token_ttl_s
        self._lock = threading.Lock()
        self._live: dict[str, AdmissionTicket] = {}
        self.audit: list[dict] = []
        self._db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS consumed_tokens(nonce TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, consumed_at REAL NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS revoked_attempts(attempt_id TEXT PRIMARY KEY, revoked_at REAL NOT NULL)")

    def claim_issuer(self) -> _IssuerCapability:
        with self._lock:
            if self._cap_claimed:
                raise PermissionError("EXEC-INV-01: issuer capability already bound to the single GovernedDispatcher")
            self._cap_claimed = True
            return self._cap

    def _sign(self, body: str) -> str:
        return hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def issue(self, cap, *, attempt_id: str, decision_id: str, input_digest: str, program_digest: str) -> str:
        if cap is not self._cap:
            raise PermissionError("EXEC-INV-01: only the GovernedDispatcher may mint admission tokens")
        payload = {"aid": attempt_id, "did": decision_id, "in": input_digest, "pg": program_digest,
                   "exp": time.time() + self._ttl, "nonce": secrets.token_hex(16)}
        body = _b64e(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        return f"{body}.{self._sign(body)}"

    def revoke_attempt(self, attempt_id: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO revoked_attempts VALUES (?, ?)", (attempt_id, time.time()))

    def _deny(self, code: str, attempt_id, detail: str = "") -> NoReturn:
        self.audit.append({"ts": time.time(), "attempt_id": attempt_id, "result": "REJECTED", "code": code})
        raise AdmissionDenied(code, detail)

    def admit(self, token, *, attempt_id: str, input_digest: str, program_digest: str) -> AdmissionTicket:
        if not isinstance(token, str) or len(token) > 8192 or token.count(".") != 1:
            self._deny("NO_VALID_DISPATCH_AUTHORIZATION", attempt_id)
        body, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, self._sign(body)):
            self._deny("BAD_SIGNATURE", attempt_id)
        try:
            p = json.loads(_b64d(body))
        except Exception:
            self._deny("MALFORMED_TOKEN", attempt_id)
        if not isinstance(p, dict) or any(k not in p for k in _REQUIRED):
            self._deny("MALFORMED_TOKEN", attempt_id)

        # Validate every security-sensitive field before comparisons or DB use.
        if not all(isinstance(p[k], str) and p[k] for k in ("aid", "did", "in", "pg", "nonce")):
            self._deny("MALFORMED_TOKEN", attempt_id)
        if len(p["nonce"]) > 128 or len(p["aid"]) > 256 or len(p["did"]) > 256:
            self._deny("MALFORMED_TOKEN", attempt_id)
        if not isinstance(p["exp"], (int, float)) or isinstance(p["exp"], bool):
            self._deny("MALFORMED_TOKEN", attempt_id)
        if not math.isfinite(p["exp"]):
            self._deny("MALFORMED_TOKEN", attempt_id)
        if time.time() > p["exp"]:
            self._deny("TOKEN_EXPIRED", attempt_id)
        if p["aid"] != attempt_id:
            self._deny("ATTEMPT_BINDING_MISMATCH", attempt_id)
        if p["in"] != input_digest or p["pg"] != program_digest:
            self._deny("DIGEST_BINDING_MISMATCH", attempt_id)
        with self._lock:
            if self._db.execute("SELECT 1 FROM revoked_attempts WHERE attempt_id=?", (attempt_id,)).fetchone():
                self._deny("ATTEMPT_REVOKED", attempt_id)
            try:
                self._db.execute("INSERT INTO consumed_tokens VALUES (?, ?, ?)", (p["nonce"], attempt_id, time.time()))
            except sqlite3.IntegrityError:
                self._deny("TOKEN_REPLAY", attempt_id)
            ticket = AdmissionTicket(secrets.token_hex(16), attempt_id, p["did"], p["in"], p["pg"], time.time())
            self._live[ticket.ticket_id] = ticket
        self.audit.append({"ts": time.time(), "attempt_id": attempt_id, "result": "ADMITTED", "code": "OK"})
        return ticket

    def redeem(self, ticket) -> bool:
        if not isinstance(ticket, AdmissionTicket):
            return False
        with self._lock:
            issued = self._live.get(ticket.ticket_id)
            if issued is None or issued != ticket:
                return False
            del self._live[ticket.ticket_id]
            return True
