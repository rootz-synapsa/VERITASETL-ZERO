"""RR-AT-04: same run/attempt dispatched twice -> at most one successful dispatch."""
from __future__ import annotations

import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from packages.admission.admission import AdmissionDenied  # noqa: E402
from tests.acceptance.common import Recorder, build_system, dispatch_job, new_job  # noqa: E402

EXEC = "EXECUTED_AWAITING_VERIFICATION"


def expect_denied(fn):
    try:
        fn()
        return None
    except AdmissionDenied as e:
        return e.code


def main() -> int:
    rec = Recorder("RR-AT-04", "Replay / duplicate dispatch is blocked",
                   "At most one successful dispatch per attempt; decisions, tokens and tickets are single-use")
    with tempfile.TemporaryDirectory() as td:
        s = build_system(td)
        captured: dict = {}
        original_admit = s.admission.admit

        def spy(token, **kw):
            t = original_admit(token, **kw)
            captured.setdefault("token", token)
            captured.setdefault("ticket", t)
            captured.setdefault("kw", dict(kw))
            return t

        s.admission.admit = spy
        j1 = new_job(s)
        r1 = dispatch_job(s, j1, "att-001")
        del s.admission.admit
        rec.check("C1", "First dispatch of att-001 succeeds",
                  r1["status"] == EXEC and s.worker.invocations == 1,
                  {"status": r1["status"], "worker_invocations": s.worker.invocations})

        j2 = new_job(s)
        r2 = dispatch_job(s, j2, "att-001")
        rec.check("C2", "Second dispatch of same attempt_id -> REPLAY_BLOCKED, worker not invoked",
                  r2["status"] == "REPLAY_BLOCKED" and r2["worker_invoked"] is False and s.worker.invocations == 1,
                  {k: r2[k] for k in ("status", "reason", "worker_invoked", "state_trail")}
                  | {"worker_invocations": s.worker.invocations})

        j3 = new_job(s)
        r3 = dispatch_job(s, j3, "att-002", authorization=j1.decision)
        rec.check("C3", "Reusing a consumed authority decision under a new attempt_id is blocked",
                  r3["status"] == "REPLAY_BLOCKED" and r3["worker_invoked"] is False and s.worker.invocations == 1,
                  {k: r3[k] for k in ("status", "reason", "worker_invoked")})

        code = expect_denied(lambda: s.admission.admit(captured["token"], **captured["kw"]))
        rec.check("C4", "Intercepted admission token replayed -> TOKEN_REPLAY", code == "TOKEN_REPLAY",
                  {"code": code, "token_sha256": r1["admission_token_sha256"]})

        code = expect_denied(lambda: s.worker.run(captured["ticket"], j1.program, j1.data))
        rec.check("C5", "Reusing a redeemed admission ticket -> worker refuses",
                  code == "NO_VALID_ADMISSION_TICKET" and s.worker.invocations == 1,
                  {"code": code, "worker_invocations": s.worker.invocations})

        n = 16
        jobs = [new_job(s) for _ in range(n)]
        results: list = [None] * n
        barrier = threading.Barrier(n)
        before = s.worker.invocations

        def racer(i):
            barrier.wait()
            results[i] = dispatch_job(s, jobs[i], "att-race")

        threads = [threading.Thread(target=racer, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        executed = sum(1 for r in results if r and r["status"] == EXEC)
        blocked = sum(1 for r in results if r and r["status"] == "REPLAY_BLOCKED")
        delta = s.worker.invocations - before
        rec.check("C6", f"{n} concurrent dispatches of att-race -> exactly 1 executes",
                  executed == 1 and blocked == n - 1 and delta == 1,
                  {"executed": executed, "replay_blocked": blocked, "worker_invocation_delta": delta})

        rec.check("C7", "Atomic commit store holds exactly one row per attempt",
                  s.dispatcher.commit_count("att-001") == 1 and s.dispatcher.commit_count("att-race") == 1,
                  {"att-001": s.dispatcher.commit_count("att-001"), "att-race": s.dispatcher.commit_count("att-race")})
    return rec.finish()


if __name__ == "__main__":
    sys.exit(main())
