import csv
import io
from decimal import Decimal, InvalidOperation

REQUIRED = ("supplier_id", "supplier_name", "tax_id", "amount", "currency")


def repair_supplier_csv(raw: bytes) -> dict:
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("CSV must be UTF-8 encoded")

    reader = csv.DictReader(io.StringIO(source))
    if not reader.fieldnames:
        raise ValueError("CSV header is missing")

    missing = set(REQUIRED) - set(reader.fieldnames)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

    normalized = []
    exceptions = []
    seen_ids = set()
    input_count = 0

    for line_number, original in enumerate(reader, start=2):
        input_count += 1
        row = {key: (value or "").strip() for key, value in original.items()
               if key is not None}

        errors = []
        for field in REQUIRED:
            if not row.get(field):
                errors.append(f"MISSING_{field.upper()}")

        supplier_id = row.get("supplier_id", "")
        if supplier_id and supplier_id in seen_ids:
            errors.append("DUPLICATE_SUPPLIER_ID")
        elif supplier_id:
            seen_ids.add(supplier_id)

        try:
            amount = Decimal(row.get("amount", ""))
            if not amount.is_finite() or amount < 0:
                errors.append("INVALID_AMOUNT")
            else:
                row["amount"] = format(amount.quantize(Decimal("0.01")), ".2f")
        except (InvalidOperation, ValueError):
            errors.append("INVALID_AMOUNT")

        if errors:
            exceptions.append({
                "source_row": line_number,
                "supplier_id": supplier_id,
                "errors": errors,
                "original": original,
            })
        else:
            normalized.append(row)

    return {
        "normalized": normalized,
        "exceptions": exceptions,
        "summary": {
            "input_rows": input_count,
            "normalized_rows": len(normalized),
            "exception_rows": len(exceptions),
        },
    }


def verify_repair(raw: bytes, result: dict) -> dict:
    """Independent business-invariant checks on the proposed result."""
    checks = {}

    expected = repair_supplier_csv(raw)
    actual_rows = result.get("normalized", [])

    checks["row_accounting"] = (
        len(actual_rows) + len(result.get("exceptions", []))
        == expected["summary"]["input_rows"]
    )
    checks["expected_valid_rows"] = (
        len(actual_rows) == len(expected["normalized"])
    )
    checks["supplier_ids_unique"] = (
        len({r.get("supplier_id") for r in actual_rows})
        == len(actual_rows)
    )
    checks["required_fields_present"] = all(
        all(r.get(field) for field in REQUIRED)
        for r in actual_rows
    )
    checks["tax_ids_preserved"] = (
        [r.get("tax_id") for r in actual_rows]
        == [r.get("tax_id") for r in expected["normalized"]]
    )
    checks["amounts_match_expected"] = (
        [r.get("amount") for r in actual_rows]
        == [r.get("amount") for r in expected["normalized"]]
    )

    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
    }
