"""WorkerRuntime: refuses to start without a one-time ticket from WorkerAdmission.
In-process bounded executor for Steps 0-3; Step 7 swaps execution into the isolated sandbox."""
from __future__ import annotations

import time

from packages.admission.admission import AdmissionDenied, WorkerAdmission
from packages.admission.programs import BUILTIN_PROGRAMS
from packages.contracts.models import Program, sha256_bytes


class WorkerRuntime:
    def __init__(self, admission: WorkerAdmission):
        self._admission = admission
        self.invocations = 0
        self.log: list[dict] = []

    def run(self, ticket, program: Program, input_bytes: bytes) -> dict:
        if not self._admission.redeem(ticket):
            self.log.append({"ts": time.time(), "result": "REFUSED", "code": "NO_VALID_ADMISSION_TICKET"})
            raise AdmissionDenied("NO_VALID_ADMISSION_TICKET", "worker refuses to start without a one-time admission ticket")
        if program.digest != ticket.program_digest or sha256_bytes(input_bytes) != ticket.input_digest:
            raise AdmissionDenied("DIGEST_MISMATCH_AT_START")
        handler = BUILTIN_PROGRAMS.get(program.name)
        if handler is None:
            raise AdmissionDenied("UNKNOWN_PROGRAM", program.name)
        self.invocations += 1
        self.log.append({"ts": time.time(), "result": "STARTED", "attempt_id": ticket.attempt_id})
        return handler(input_bytes)
