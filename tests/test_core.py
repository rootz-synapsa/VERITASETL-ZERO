from app.core import repair_supplier_csv, verify_repair

CSV = b"""supplier_id,supplier_name,tax_id,amount,currency
 S001 , Alpha Co , 001234 , 1200.5 , THB
S002,Beta Co,009876,250.00,THB
S003,Gamma Co,123456,invalid,THB
"""


def test_repair_normalizes_valid_rows():
    result = repair_supplier_csv(CSV)
    assert result["summary"] == {
        "input_rows": 3,
        "normalized_rows": 2,
        "exception_rows": 1,
    }
    assert result["normalized"][0]["supplier_id"] == "S001"
    assert result["normalized"][0]["tax_id"] == "001234"
    assert result["normalized"][0]["amount"] == "1200.50"


def test_invalid_amount_goes_to_exceptions():
    result = repair_supplier_csv(CSV)
    assert result["exceptions"][0]["supplier_id"] == "S003"
    assert "INVALID_AMOUNT" in result["exceptions"][0]["errors"]


def test_independent_verifier_accepts_valid_result():
    result = repair_supplier_csv(CSV)
    verification = verify_repair(CSV, result)
    assert verification["status"] == "PASS"
    assert all(verification["checks"].values())


def test_verifier_rejects_tampered_result():
    result = repair_supplier_csv(CSV)
    result["normalized"][0]["amount"] = "999999.00"
    verification = verify_repair(CSV, result)
    assert verification["status"] == "FAIL"
    assert verification["checks"]["amounts_match_expected"] is False
