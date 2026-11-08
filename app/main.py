from __future__ import annotations
import json
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="VERITASETL-ZERO Judge Mode", version="3.2")
templates = Jinja2Templates(directory="app/templates")
ROOT = Path(__file__).resolve().parents[1]

@app.get("/", response_class=HTMLResponse)
def judge_dashboard(request: Request):
    index_path = ROOT / "evidence" / "index.json"
    gates = []
    updated_utc = "N/A"
    if index_path.exists():
        data = json.loads(index_path.read_text(encoding="utf-8"))
        gates = data.get("gates", [])
        updated_utc = data.get("updated_utc", "N/A")

    # โหลดตัวอย่างผลลัพธ์ C1 มาแสดงฝั่ง Business Output
    c1_norm, c1_exc = [], []
    c1_dir = ROOT / "evidence" / "ea" / "EA-04" / "C1_legit"
    if (c1_dir / "normalized.csv").exists():
        import csv
        c1_norm = list(csv.DictReader((c1_dir / "normalized.csv").open(encoding="utf-8")))
    if (c1_dir / "exceptions.csv").exists():
        import csv
        c1_exc = list(csv.DictReader((c1_dir / "exceptions.csv").open(encoding="utf-8")))

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "gates": gates,
            "updated_utc": updated_utc,
            "c1_norm": c1_norm,
            "c1_exc": c1_exc
        }
    )
