from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


REQUIRED_PATHS = (
    "README.md",
    "MIDPOINT.md",
    ".env.example",
    ".gitignore",
    ".github/workflows/ci.yml",
    "app/main.py",
    "tests/test_main.py",
    "scripts/arc_testnet_transfer.py",
    "scripts/run_edge_case_evidence.py",
    "scripts/validate_edge_case_evidence.py",
    "scripts/verify_arc_settlement.py",
)

FORBIDDEN_PARTS = {
    ".agents",
    ".codex",
    ".python313",
    ".pytest_cache",
    ".tmp",
    "__pycache__",
    "research",
    "shipline",
}

FORBIDDEN_SUFFIXES = {
    ".db",
    ".docx",
    ".pdf",
    ".pyc",
    ".sqlite",
    ".sqlite3",
}

IGNORED_WORKTREE_PARTS = {
    ".git",
    ".venv",
}

SECRET_PATTERNS = {
    "literal private key": re.compile(
        r"(?im)^\s*(?:ARC_PRIVATE_KEY|PRIVATE_KEY)\s*=\s*[\"']?"
        r"(?:0x)?[0-9a-f]{64}[\"']?\s*(?:#.*)?$"
    ),
    "literal Circle API key": re.compile(
        r"(?im)^\s*CIRCLE_API_KEY\s*=\s*[\"']?"
        r"(?!\s*(?:replace|example|your-|test-))"
        r"[A-Za-z0-9_./+=-]{20,}[\"']?\s*(?:#.*)?$"
    ),
    "PEM private key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "OpenAI-style token": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "local Windows user path": re.compile(r"(?i)\bC:\\Users\\"),
    "private Railway project identifier": re.compile(
        r"\bcb34b081-089e-4ac1-b438-99c29f9b5bc2\b", re.IGNORECASE
    ),
}

JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b"
)
BEARER_PATTERN = re.compile(
    r"(?i)\b(?:authorization\s*[:=]\s*)?bearer\s+"
    r"(?P<value>[^\s\"'`,;]+)"
)
COOKIE_HEADER_PATTERN = re.compile(
    r"(?i)\b(?P<kind>set-cookie|cookie)[\"']?\s*[:=]\s*[\"']?"
    r"(?P<value>[^\s\"'`,;]+)"
)
OAUTH_CODE_QUERY_PATTERN = re.compile(
    r"(?i)(?:[?&](?:code|authorization_code|auth_code)|"
    r"\b(?:authorization_code|auth_code|oauth_code))\s*=\s*[\"']?"
    r"(?P<value>[^\s\"'`,;&#]+)"
)
EMAIL_PATTERN = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
)

NAMED_VALUE_KEYS = (
    r"access[_-]?token|refresh[_-]?token|oauth[_-]?token|bearer[_-]?token|"
    r"id[_-]?token|authorization[_-]?code|auth[_-]?code|oauth[_-]?code|"
    r"device[_-]?code|receipt[_-]?token|payment[_-]?receipt|"
    r"x[_-]?payment[_-]?receipt|spend[_-]?token|"
    r"spend[_-]?authorization[_-]?token|x[_-]?spend[_-]?token|"
    r"cookie|cookies|session|session[_-]?id|session[_-]?token|"
    r"session[_-]?cookie|csrf[_-]?token|otp|otp[_-]?code|totp|"
    r"one[_-]?time[_-]?password|verification[_-]?code|mfa[_-]?code|"
    r"email|email[_-]?address"
)
QUOTED_NAMED_VALUE_PATTERN = re.compile(
    rf"(?i)(?<![A-Z0-9_-])[\"']?(?P<key>{NAMED_VALUE_KEYS})[\"']?"
    rf"\s*(?:=|:)\s*(?P<quote>[\"'`])(?P<value>[^\"'`\r\n]+)(?P=quote)"
)
BARE_NAMED_VALUE_PATTERN = re.compile(
    rf"(?im)^\s*[\"']?(?P<key>{NAMED_VALUE_KEYS})[\"']?"
    rf"\s*(?:=|:)\s*(?P<value>[^\s,;#]+)\s*,?\s*(?:#.*)?$"
)
SENSITIVE_ENV_ASSIGNMENT_PATTERN = re.compile(
    r"(?m)^\s*(?:export\s+|\$env:)?"
    r"(?P<key>[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|"
    r"API_KEY|AUTH_CODE|AUTHORIZATION_CODE|OTP|EMAIL|COOKIE|SESSION|"
    r"CREDENTIAL|CREDENTIALS|DSN|DATABASE_URL))\s*=\s*"
    r"(?P<value>[^\r\n#]+?)\s*(?:#.*)?$"
)

PLACEHOLDER_WORD_PATTERN = re.compile(
    r"(?i)(?:^|[-_./\s])(?:change[-_]?me|configured|demo|dummy|example|"
    r"fake|fixture|local|masked|opaque|placeholder|redacted|replace(?:[-_]?with)?|"
    r"sample|test(?:[-_]?only)?|unset|your)(?:$|[-_./\s])"
)
PLACEHOLDER_EMAIL_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
}


def _clean_candidate(value: str) -> str:
    return value.strip().strip("\"'`").rstrip(",;")


def _is_placeholder(value: str, *, path: Path) -> bool:
    candidate = _clean_candidate(value)
    lowered = candidate.lower()
    if not candidate or lowered in {"none", "null", "nil", "n/a", "na"}:
        return True
    if (
        candidate.startswith(("<", "${", "{{", "[[", "$(", "%"))
        or candidate.endswith((">", "}}", "]]"))
        or re.fullmatch(r"[*xX._-]{4,}", candidate)
    ):
        return True
    if PLACEHOLDER_WORD_PATTERN.search(candidate):
        return True
    if re.fullmatch(r"(?:0{4,}|1?23456(?:78)?|654321)", candidate):
        return True

    email_match = EMAIL_PATTERN.fullmatch(candidate)
    if email_match:
        domain = candidate.rsplit("@", 1)[1].lower()
        if (
            domain in PLACEHOLDER_EMAIL_DOMAINS
            or domain.endswith((".example", ".invalid", ".test"))
        ):
            return True

    # Keep the committed local-development DSN in .env.example from becoming
    # a false positive while still rejecting credentialed non-local DSNs.
    if path.name.endswith(".example") and "localhost" in lowered:
        if re.search(r":(?:[^@/]*(?:password|passwd))@", lowered):
            return True
    return False


def _label_for_key(key: str) -> str:
    normalized = key.lower().replace("-", "_")
    if key.isupper() and "_" in key:
        return "sensitive environment assignment"
    if "receipt" in normalized:
        return "payment receipt token"
    if "spend" in normalized:
        return "spend authorization token"
    if normalized in {
        "authorization_code",
        "auth_code",
        "oauth_code",
        "device_code",
    }:
        return "OAuth authorization code"
    if normalized == "refresh_token":
        return "OAuth refresh token"
    if normalized in {
        "access_token",
        "oauth_token",
        "bearer_token",
        "id_token",
    }:
        return "OAuth bearer/access token"
    if "cookie" in normalized or normalized == "cookies":
        return "cookie material"
    if "session" in normalized or normalized == "csrf_token":
        return "session material"
    if normalized in {
        "otp",
        "otp_code",
        "totp",
        "one_time_password",
        "verification_code",
        "mfa_code",
    }:
        return "one-time password"
    if normalized in {"email", "email_address"}:
        return "email address"
    return "sensitive environment assignment"


def _is_likely_secret(label: str, value: str, *, path: Path) -> bool:
    candidate = _clean_candidate(value)
    if _is_placeholder(candidate, path=path):
        return False
    # Bare source expressions are references to runtime material, not persisted
    # values. Quoted literals reach this function without these delimiters.
    if any(character in candidate for character in "()[]{}"):
        return False
    if (
        path.suffix.lower() in {".js", ".jsx", ".py", ".ts", ".tsx"}
        and label != "one-time password"
        and re.fullmatch(
            r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*",
            candidate,
        )
    ):
        return False
    if label == "email address":
        return EMAIL_PATTERN.fullmatch(candidate) is not None
    if label == "one-time password":
        return re.fullmatch(r"[A-Za-z0-9]{4,12}", candidate) is not None
    if label == "cookie material":
        secret_part = candidate.split("=", 1)[-1]
        return len(secret_part) >= 12
    minimum_length = {
        "OAuth authorization code": 10,
        "sensitive environment assignment": 8,
    }.get(label, 12)
    return len(candidate) >= minimum_length


def _contextual_secret_findings(text: str, *, path: Path) -> set[str]:
    findings: set[str] = set()

    if JWT_PATTERN.search(text):
        findings.add("JWT-like token")

    for match in BEARER_PATTERN.finditer(text):
        if _is_likely_secret(
            "OAuth bearer/access token", match.group("value"), path=path
        ):
            findings.add("OAuth bearer/access token")

    for match in COOKIE_HEADER_PATTERN.finditer(text):
        if _is_likely_secret("cookie material", match.group("value"), path=path):
            findings.add("cookie material")

    for match in OAUTH_CODE_QUERY_PATTERN.finditer(text):
        if _is_likely_secret(
            "OAuth authorization code", match.group("value"), path=path
        ):
            findings.add("OAuth authorization code")

    for pattern in (QUOTED_NAMED_VALUE_PATTERN, BARE_NAMED_VALUE_PATTERN):
        for match in pattern.finditer(text):
            label = _label_for_key(match.group("key"))
            if _is_likely_secret(label, match.group("value"), path=path):
                findings.add(label)

    for match in SENSITIVE_ENV_ASSIGNMENT_PATTERN.finditer(text):
        if _is_likely_secret(
            "sensitive environment assignment", match.group("value"), path=path
        ):
            findings.add("sensitive environment assignment")

    for match in EMAIL_PATTERN.finditer(text):
        if not _is_placeholder(match.group(0), path=path):
            findings.add("email address")

    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit a prepared Safe4 public demo repository."
    )
    parser.add_argument("repository", type=Path)
    return parser.parse_args()


def is_forbidden_path(path: Path, root: Path) -> str | None:
    relative = path.relative_to(root)
    lowered_parts = {part.lower() for part in relative.parts}
    blocked = lowered_parts.intersection(FORBIDDEN_PARTS)
    if blocked:
        return f"forbidden path component: {sorted(blocked)[0]}"
    if path.name == ".env":
        return "committed .env file"
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return f"forbidden file type: {path.suffix.lower()}"
    return None


def scan_text(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    findings: set[str] = set()
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.add(label)
    findings.update(_contextual_secret_findings(text, path=path))
    return sorted(findings)


def repository_files(root: Path) -> list[Path]:
    if (root / ".git").is_dir():
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"git ls-files failed: {message}")
        return [
            root / relative.decode("utf-8")
            for relative in result.stdout.split(b"\0")
            if relative
        ]

    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not set(path.relative_to(root).parts).intersection(IGNORED_WORKTREE_PARTS)
    ]


def main() -> int:
    args = parse_args()
    root = args.repository.resolve()
    if not root.is_dir():
        print(f"PUBLIC_AUDIT_FAIL: repository not found: {root}", file=sys.stderr)
        return 1

    issues: list[str] = []
    for required in REQUIRED_PATHS:
        if not (root / required).is_file():
            issues.append(f"missing required file: {required}")

    try:
        files = repository_files(root)
    except RuntimeError as exc:
        print(f"PUBLIC_AUDIT_FAIL: {exc}", file=sys.stderr)
        return 1
    for path in files:
        relative = path.relative_to(root)
        path_issue = is_forbidden_path(path, root)
        if path_issue:
            issues.append(f"{relative}: {path_issue}")
            continue
        for finding in scan_text(path):
            issues.append(f"{relative}: possible {finding}")

    if issues:
        print("PUBLIC_AUDIT_FAIL")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print(
        "PUBLIC_AUDIT_OK "
        f"files={len(files)} required={len(REQUIRED_PATHS)} secrets=0 forbidden=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
