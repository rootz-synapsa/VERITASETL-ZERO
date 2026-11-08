"""Bounded built-in programs. Program digest = sha256(name + exact source of the program and its helpers)."""
from __future__ import annotations

import csv
import hashlib
import inspect
import io
import re
from datetime import date
from decimal import Decimal

from packages.contracts.models import Program


def row_count_v1(data: bytes) -> dict:
    rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
    return {"program": "row_count_v1", "rows_total": len(rows),
            "data_rows": max(len(rows) - 1, 0), "header": rows[0] if rows else []}


def _sr_clean_id(raw):
    s = re.sub(r"[\s\-_]", "", (raw or "").upper())
    m = re.fullmatch(r"S(\d{1,6})", s)
    if not m:
        return None
    return "S" + str(int(m.group(1))).zfill(4)


def _sr_clean_name(raw):
    return " ".join((raw or "").split())


def _sr_clean_tax(raw):
    s = re.sub(r"[\s\-]", "", raw or "")
    return s if re.fullmatch(r"\d{13}", s) else None


def _sr_parse_date(raw):
    s = (raw or "").strip()
    if not s:
        return None, "MISSING_INVOICE_DATE"
    months = {"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
              "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12}
    try:
        m = re.fullmatch(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", s)
        if m:
            return date(int(m[1]), int(m[2]), int(m[3])).isoformat(), None
        m = re.fullmatch(r"(\d{1,2})[/-](\d{1,2})[/-](\d{4})", s)
        if m:
            day, month, year = int(m[1]), int(m[2]), int(m[3])
            if day <= 12 and month <= 12 and day != month:
                return None, "AMBIGUOUS_DATE"
            return date(year, month, day).isoformat(), None
        m = re.fullmatch(r"(\d{1,2})[\s\-]([A-Za-z]{3})[\s\-](\d{4})", s)
        if m and m[2].upper() in months:
            return date(int(m[3]), months[m[2].upper()], int(m[1])).isoformat(), None
    except ValueError:
        return None, "INVALID_DATE"
    return None, "INVALID_DATE"


def _sr_parse_amount(raw):
    s = re.sub(r"(?i)^THB", "", (raw or "").strip()).replace(" ", "")
    if not s:
        return None, "MISSING_AMOUNT"
    if s.startswith("-") or s.startswith("("):
        return None, "NEGATIVE_AMOUNT"
    if re.fullmatch(r"\d{1,3}(,\d{3})+(\.\d{1,2})?", s) or re.fullmatch(r"\d+(\.\d{1,2})?", s):
        return Decimal(s.replace(",", "")).quantize(Decimal("0.01")), None
    if re.fullmatch(r"\d{1,3}(\.\d{3})+(,\d{1,2})?", s) or re.fullmatch(r"\d+,\d{1,2}", s):
        return None, "AMBIGUOUS_AMOUNT_FORMAT"
    if re.fullmatch(r"\d+\.\d{3,}", s):
        return None, "AMBIGUOUS_AMOUNT_PRECISION"
    return None, "INVALID_AMOUNT"


def supplier_repair_v1(data: bytes) -> dict:
    """Deterministic bounded supplier CSV repair. Ambiguous or unsafe rows are routed to
    REQUIRES_REVIEW and never guessed. The worker reports a claim, not a verdict."""
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    required = ("supplier_id", "supplier_name", "tax_id", "invoice_date", "amount", "currency")
    missing = [c for c in required if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError("missing required columns: " + ",".join(missing))
    staged = []
    for raw in reader:
        reasons = []
        sid = _sr_clean_id(raw.get("supplier_id"))
        if sid is None:
            reasons.append("INVALID_SUPPLIER_ID")
        name = _sr_clean_name(raw.get("supplier_name"))
        if not name:
            reasons.append("MISSING_SUPPLIER_NAME")
        tax = _sr_clean_tax(raw.get("tax_id"))
        if tax is None:
            reasons.append("INVALID_TAX_ID")
        inv_date, why = _sr_parse_date(raw.get("invoice_date"))
        if why:
            reasons.append(why)
        amount, why = _sr_parse_amount(raw.get("amount"))
        if why:
            reasons.append(why)
        cur = (raw.get("currency") or "").strip().upper()
        if not cur:
            reasons.append("MISSING_CURRENCY")
        elif cur != "THB":
            reasons.append("UNSUPPORTED_CURRENCY")
        staged.append({"source_row": reader.line_num, "raw": raw, "supplier_id": sid, "supplier_name": name,
                       "tax_id": tax, "invoice_date": inv_date, "amount": amount, "currency": cur,
                       "reasons": reasons})
    id_counts = {}
    for r in staged:
        if r["supplier_id"]:
            id_counts[r["supplier_id"]] = id_counts.get(r["supplier_id"], 0) + 1
    for r in staged:
        if r["supplier_id"] and id_counts[r["supplier_id"]] > 1:
            r["reasons"].append("DUPLICATE_SUPPLIER_ID")
    norm_buf, exc_buf = io.StringIO(), io.StringIO()
    nw = csv.writer(norm_buf, lineterminator="\n")
    ew = csv.writer(exc_buf, lineterminator="\n")
    nw.writerow(["source_row", "supplier_id", "supplier_name", "tax_id", "invoice_date", "amount", "currency"])
    ew.writerow(["source_row", "status", "reason", "raw_supplier_id", "raw_supplier_name", "raw_tax_id",
                 "raw_invoice_date", "raw_amount", "raw_currency"])
    total = Decimal("0.00")
    n_norm = n_rev = 0
    reason_counts = {}
    for r in staged:
        if r["reasons"]:
            n_rev += 1
            for x in r["reasons"]:
                reason_counts[x] = reason_counts.get(x, 0) + 1
            ew.writerow([r["source_row"], "REQUIRES_REVIEW", "|".join(r["reasons"])]
                        + [(r["raw"].get(c) or "") for c in required])
        else:
            n_norm += 1
            total += r["amount"]
            nw.writerow([r["source_row"], r["supplier_id"], r["supplier_name"], r["tax_id"],
                         r["invoice_date"], format(r["amount"], "f"), r["currency"]])
    summary = {
        "program": "supplier_repair_v1",
        "input_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "input_rows": len(staged),
        "normalized_rows": n_norm,
        "review_rows": n_rev,
        "normalized_total": format(total, "f"),
        "currency": "THB",
        "review_reasons": dict(sorted(reason_counts.items())),
        "worker_claim": "EXECUTION_COMPLETE_UNVERIFIED",
        "self_certified": False,
    }
    return {"normalized_csv": norm_buf.getvalue(), "exceptions_csv": exc_buf.getvalue(), "job_summary": summary}


def supplier_repair_naive_v0(data: bytes) -> dict:
    """DEMO FAULT INJECTION (G5). A naive repair that guesses instead of routing ambiguous rows to review.
    It returns normally, which shows that a clean exit is not business correctness."""
    rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source_row", "supplier_id", "supplier_name", "tax_id", "invoice_date", "amount", "currency"])
    total = Decimal("0.00")
    for i, r in enumerate(rows, start=2):
        raw_amount = re.sub(r"(?i)thb", "", r.get("amount") or "").replace(",", "").strip() or "0"
        amount = Decimal(raw_amount).quantize(Decimal("0.01"))
        total += amount
        w.writerow([i, (r.get("supplier_id") or "").strip().upper(), (r.get("supplier_name") or "").strip(),
                    (r.get("tax_id") or "").strip(), (r.get("invoice_date") or "").strip(),
                    format(amount, "f"), (r.get("currency") or "").strip().upper()])
    ebuf = io.StringIO()
    csv.writer(ebuf, lineterminator="\n").writerow(
        ["source_row", "status", "reason", "raw_supplier_id", "raw_supplier_name", "raw_tax_id",
         "raw_invoice_date", "raw_amount", "raw_currency"])
    summary = {
        "program": "supplier_repair_naive_v0",
        "input_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "input_rows": len(rows),
        "normalized_rows": len(rows),
        "review_rows": 0,
        "normalized_total": format(total, "f"),
        "currency": "THB",
        "review_reasons": {},
        "worker_claim": "EXECUTION_COMPLETE_UNVERIFIED",
        "self_certified": False,
    }
    return {"normalized_csv": buf.getvalue(), "exceptions_csv": ebuf.getvalue(), "job_summary": summary}


BUILTIN_PROGRAMS = {
    "row_count_v1": row_count_v1,
    "supplier_repair_v1": supplier_repair_v1,
    "supplier_repair_naive_v0": supplier_repair_naive_v0,
}

PROGRAM_PARTS = {
    "row_count_v1": (row_count_v1,),
    "supplier_repair_v1": (_sr_clean_id, _sr_clean_name, _sr_clean_tax, _sr_parse_date, _sr_parse_amount,
                           supplier_repair_v1),
    "supplier_repair_naive_v0": (supplier_repair_naive_v0,),
}


def builtin_program(name: str) -> Program:
    return Program(name=name, source="".join(inspect.getsource(f) for f in PROGRAM_PARTS[name]))
