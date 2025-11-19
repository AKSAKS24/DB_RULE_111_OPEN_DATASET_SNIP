from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI(
    title="Rule 111 — OPEN DATASET without MODE/ENCODING",
    version="2.0"
)

# ---------------------------------------------------------------------------
# Models (aligned with reference: header + findings)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None      # OpenDatasetNoMode / OpenDatasetTextNoEncoding
    severity: Optional[str] = None         # always "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None          # full line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which
    that match occurs (no extra lines).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1  # right after '\n'

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


# ---------------------------------------------------------------------------
# Rule detection logic
# ---------------------------------------------------------------------------
STMT_RE      = re.compile(r"(?is)\bOPEN\s+DATASET\b[^.]*\.", re.DOTALL)
MODE_RE      = re.compile(r"(?i)\bIN\s+(TEXT|BINARY)\s+MODE\b")
TEXT_MODE_RE = re.compile(r"(?i)\bIN\s+TEXT\s+MODE\b")
ENCODING_RE  = re.compile(r"(?i)\bENCODING\b\s+\S+")


def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings: List[Finding] = []

    base_start = unit.start_line or 0  # block start line in program

    for m in STMT_RE.finditer(src):
        stmt_start = m.start()
        stmt_end = m.end()
        stmt = m.group(0)

        has_mode     = MODE_RE.search(stmt) is not None
        is_text_mode = TEXT_MODE_RE.search(stmt) is not None
        has_encoding = ENCODING_RE.search(stmt) is not None

        # Line within this block (1-based)
        line_in_block = src[:stmt_start].count("\n") + 1

        # Snippet = full line containing the OPEN DATASET statement
        snippet_line = get_line_snippet(src, stmt_start, stmt_end)
        snippet_line_count = snippet_line.count("\n") + 1  # usually 1

        # Absolute line numbers in full program
        starting_line_abs = base_start + line_in_block
        ending_line_abs = base_start + line_in_block + snippet_line_count

        # 1) Missing MODE addition (no TEXT/BINARY MODE at all)
        if not has_mode:
            msg = "OPEN DATASET without MODE. Specify IN TEXT MODE or IN BINARY MODE and, for text, an explicit ENCODING."
            sug = (
                "OPEN DATASET lv_file FOR OUTPUT IN TEXT MODE ENCODING UTF-8.\n"
                "* or *\n"
                "OPEN DATASET lv_file FOR INPUT IN BINARY MODE."
            )

            findings.append(
                Finding(
                    prog_name=unit.pgm_name,
                    incl_name=unit.inc_name,
                    types=unit.type,
                    blockname=unit.name,
                    starting_line=starting_line_abs,
                    ending_line=ending_line_abs,
                    issues_type="OpenDatasetNoMode",
                    severity="error",
                    message=msg,
                    suggestion=sug,
                    snippet=snippet_line.replace("\n", "\\n"),
                )
            )
            # skip further checks for this statement
            continue

        # 2) Text mode without encoding (always enforce)
        if is_text_mode and not has_encoding:
            msg = "OPEN DATASET in TEXT MODE without explicit ENCODING."
            sug = "Add ENCODING UTF-8 (or the required code page)."

            findings.append(
                Finding(
                    prog_name=unit.pgm_name,
                    incl_name=unit.inc_name,
                    types=unit.type,
                    blockname=unit.name,
                    starting_line=starting_line_abs,
                    ending_line=ending_line_abs,
                    issues_type="OpenDatasetTextNoEncoding",
                    severity="error",
                    message=msg,
                    suggestion=sug,
                    snippet=snippet_line.replace("\n", "\\n"),
                )
            )

    out_unit = Unit(**unit.model_dump())
    out_unit.findings = findings
    return out_unit


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def scan_rule111_array(units: List[Unit] = Body(...)):
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def scan_rule111_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rule": 111, "version": "2.0"}
