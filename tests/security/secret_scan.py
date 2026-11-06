"""Secret leak scanner. Never prints secret values, only finding labels."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

_PATTERNS = [
    ("openai_style_key", re.compile(r"sk-[A-Za-z0-9_\-]{16,}")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
    ("vultr_key_assignment", re.compile(r"(?i)vultr[_-]?(?:inference[_-]?)?api[_-]?key\s*[=:]\s*[\"']?[A-Za-z0-9]{16,}")),
]
_KEYVAL = re.compile(r'(?i)"(api[_-]?key|authorization|secret|access[_-]?token)"\s*:\s*"([^"]{8,})"')
_REDACTED = re.compile(r"(?i)redact|\*\*\*|<hidden>|xxxx")
ENV_NAMES = ("VULTR_API_KEY", "VULTR_INFERENCE_API_KEY", "VULTR_INFERENCE_KEY", "OPENAI_API_KEY")


def scan_text(text: str) -> list[str]:
    findings: list[str] = []
    for label, rx in _PATTERNS:
        if rx.search(text):
            findings.append(f"pattern:{label}")
    for m in _KEYVAL.finditer(text):
        if not _REDACTED.search(m.group(2)):
            findings.append(f"keyvalue:{m.group(1)}")
    for name in ENV_NAMES:
        val = os.environ.get(name, "")
        if len(val) >= 8 and val in text:
            findings.append(f"env_value:{name}")
    return findings


def scan_paths(paths: list[Path]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for root in paths:
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            hits = scan_text(text)
            if hits:
                result[str(f)] = hits
    return result


if __name__ == "__main__":
    targets = [Path(a) for a in sys.argv[1:]] or [Path("evidence")]
    leaks = scan_paths(targets)
    if leaks:
        for f, hits in leaks.items():
            print(f"LEAK {f}: {', '.join(hits)}")
        print("SECRET SCAN: FAIL")
        sys.exit(1)
    print("SECRET SCAN: PASS (0 findings)")
