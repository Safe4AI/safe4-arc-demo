"""Generate the x402/payment reason-code reference from source, not by hand.

Scans app/*.py for every payment-authorization decision call (deny_payment,
HTTPException, and x402 receipt-verification reason codes) and extracts the
HTTP status, machine-readable code, and human message actually present in the
source, so docs/x402/CONTRACT.md's reason-code table cannot silently drift
from the code that produces it.

Usage:
    python scripts/generate_x402_reason_codes.py            # print markdown table
    python scripts/generate_x402_reason_codes.py --check     # exit 1 if CONTRACT.md is stale
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "x402" / "CONTRACT.md"

# Only files actually on the POST /pay and /demo/live/settle call paths, so
# this stays a caller-facing contract, not a dump of every reason code in the
# whole application (MCP CRUD, audit export, HITL admin, etc. are separate
# APIs a /pay caller cannot reach).
SOURCE_FILES = [
    "app/main.py",
    "app/payment_flow.py",
    "app/payment_entry_checks.py",
    "app/payment_finalize.py",
    "app/protocols/x402.py",
    "app/protocols/ap2.py",
    "app/mcp/payment_policy.py",
    "app/hitl_policy.py",
    "app/api/demo_live.py",
    "app/core/intent.py",
]

# Tokens that match the ALL_CAPS_SNAKE shape but are not reason codes.
NON_CODE_TOKENS = {
    "USDC",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "TRUE",
    "FALSE",
    "NONE",
    "UTF",
}

BEGIN_MARKER = "<!-- BEGIN GENERATED REASON CODES -->"
END_MARKER = "<!-- END GENERATED REASON CODES -->"

CODE_TOKEN_RE = re.compile(r'"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,})"')
# A quoted string immediately after a code token (only a comma/whitespace/
# newline between), i.e. a positional message argument right next to a
# positional code argument -- not a general scan-ahead.
ADJACENT_STRING_RE = re.compile(r'\s*,\s*"([^"]{6,})"')
STATUS_RE = re.compile(r"status_code\s*=\s*(?:status\.HTTP_(\d{3})|(\d{3}))")
MESSAGE_RE = re.compile(r'message\s*=\s*"([^"]+)"')
ASSIGNS_CODE_RE = re.compile(
    r"(?:error_code|audit_reason_code|reason_code|\"code\")\s*[=:]"
    r"|error_payload\(\s*request\s*,\s*"
)


def _enclosing_open_paren(text: str, offset: int) -> int | None:
    """Return the index of the nearest unmatched '(' before offset."""
    depth = 0
    i = offset
    while i >= 0:
        ch = text[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                return i
            depth -= 1
        i -= 1
    return None


def _call_from_open_paren(text: str, open_index: int) -> str:
    depth = 0
    for j in range(open_index, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[open_index : j + 1]
    return text[open_index:]


def enclosing_call(text: str, code_offset: int) -> str:
    """Return the innermost balanced-paren call/constructor around code_offset.

    Scans backward to find the nearest unmatched '(' before the code
    assignment, then forward to its matching ')', so the message extracted
    next to it belongs to the *same* call and not a neighboring one.
    """
    open_index = _enclosing_open_paren(text, code_offset)
    if open_index is None:
        return text[max(0, code_offset - 300) : code_offset + 300]
    return _call_from_open_paren(text, open_index)


def find_status_climbing(text: str, code_offset: int, *, max_levels: int = 4) -> str:
    """Search outward through up to max_levels enclosing calls for status_code=.

    Reason codes are sometimes positional args to an inner helper (e.g.
    error_payload(request, "CODE", "message")) while the HTTP status is a
    kwarg on the *outer* JSONResponse(status_code=..., content=error_payload(...))
    call, so a single innermost-call scope can miss it.
    """
    offset = code_offset
    for _ in range(max_levels):
        open_index = _enclosing_open_paren(text, offset)
        if open_index is None:
            break
        call_text = _call_from_open_paren(text, open_index)
        match = STATUS_RE.search(call_text)
        if match:
            return next((g for g in match.groups() if g), "?")
        offset = open_index - 1
    return "?"


def collect_reason_codes() -> dict[str, dict[str, str]]:
    codes: dict[str, dict[str, str]] = {}
    for relative in SOURCE_FILES:
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        for assign_match in ASSIGNS_CODE_RE.finditer(text):
            # The code literal is the first quoted CODE token after this
            # assignment operator, on the same line.
            line_end = text.find("\n", assign_match.end())
            if line_end == -1:
                line_end = len(text)
            code_match = CODE_TOKEN_RE.search(text, assign_match.end(), line_end)
            if not code_match:
                continue
            code = code_match.group(1)
            if code in NON_CODE_TOKENS:
                continue
            call_text = enclosing_call(text, assign_match.start())
            status = find_status_climbing(text, assign_match.start())
            message_match = MESSAGE_RE.search(call_text)
            if message_match:
                message = message_match.group(1)
            else:
                # Positional message: a quoted string immediately following
                # the code token, separated only by a comma/whitespace (e.g.
                # error_payload(request, "CODE", "message", ...)). Anchored
                # tightly so this can't drift onto unrelated later content.
                adjacent = ADJACENT_STRING_RE.match(text, code_match.end())
                candidate = adjacent.group(1) if adjacent else ""
                # Real messages are sentences (contain a space); a bare
                # identifier like "family_id" is a dict key, not a message.
                message = candidate if " " in candidate else ""
            existing = codes.get(code)
            if existing is None or (not existing.get("message") and message):
                codes[code] = {
                    "status": status,
                    "message": message,
                    "source": relative,
                }
    return codes


def render_table(codes: dict[str, dict[str, str]]) -> str:
    lines = ["| Reason code | HTTP status | Meaning | Source |", "|---|---|---|---|"]
    for code in sorted(codes):
        info = codes[code]
        message = info["message"] or "_(see source)_"
        lines.append(f"| `{code}` | {info['status']} | {message} | `{info['source']}` |")
    return "\n".join(lines)


def main() -> int:
    codes = collect_reason_codes()
    table = render_table(codes)
    check_mode = "--check" in sys.argv

    if not check_mode:
        print(f"<!-- generated by scripts/generate_x402_reason_codes.py, {len(codes)} codes -->")
        print(table)
        return 0

    if not CONTRACT_PATH.exists():
        print(f"MISSING {CONTRACT_PATH}")
        return 1
    contract_text = CONTRACT_PATH.read_text(encoding="utf-8")
    if BEGIN_MARKER not in contract_text or END_MARKER not in contract_text:
        print(f"MISSING generated-section markers in {CONTRACT_PATH}")
        return 1
    before, rest = contract_text.split(BEGIN_MARKER, 1)
    _, after = rest.split(END_MARKER, 1)
    expected = f"{before}{BEGIN_MARKER}\n{table}\n{END_MARKER}{after}"
    if expected != contract_text:
        print("STALE: docs/x402/CONTRACT.md reason-code table does not match source.")
        print("Run: python scripts/generate_x402_reason_codes.py --write")
        return 1
    print(f"OK: {len(codes)} reason codes match source")
    return 0


def write() -> int:
    codes = collect_reason_codes()
    table = render_table(codes)
    contract_text = CONTRACT_PATH.read_text(encoding="utf-8")
    before, rest = contract_text.split(BEGIN_MARKER, 1)
    _, after = rest.split(END_MARKER, 1)
    CONTRACT_PATH.write_text(
        f"{before}{BEGIN_MARKER}\n{table}\n{END_MARKER}{after}", encoding="utf-8"
    )
    print(f"Wrote {len(codes)} reason codes to {CONTRACT_PATH}")
    return 0


if __name__ == "__main__":
    if "--write" in sys.argv:
        raise SystemExit(write())
    raise SystemExit(main())
