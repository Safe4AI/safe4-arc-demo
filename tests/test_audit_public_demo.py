from __future__ import annotations

from pathlib import Path

import pytest

from scripts.audit_public_demo import scan_text


def _scan(tmp_path: Path, text: str, *, name: str = "evidence.txt") -> set[str]:
    candidate = tmp_path / name
    candidate.write_text(text, encoding="utf-8")
    return set(scan_text(candidate))


@pytest.mark.parametrize(
    ("key", "prefix", "label"),
    [
        ("access_token", "atk_", "OAuth bearer/access token"),
        ("refresh_token", "rtk_", "OAuth refresh token"),
        ("authorization_code", "oauth_", "OAuth authorization code"),
        ("receipt_token", "receipt_", "payment receipt token"),
        ("spend_authorization_token", "spend_", "spend authorization token"),
        ("session_id", "session_", "session material"),
    ],
)
def test_detects_named_persisted_security_material(
    tmp_path: Path,
    key: str,
    prefix: str,
    label: str,
) -> None:
    value = prefix + ("A" * 32)
    assert label in _scan(tmp_path, f'{key} = "{value}"\n')


def test_detects_headers_jwt_otp_email_and_sensitive_env(tmp_path: Path) -> None:
    bearer = "bearer_" + ("B" * 32)
    cookie = "session=" + ("C" * 32)
    jwt = ".".join(("eyJ" + ("a" * 12), "eyJ" + ("b" * 12), "c" * 32))
    email = "judge.person" + "@" + "real-company.com"
    env_secret = "prod_" + ("D" * 32)
    text = "\n".join(
        (
            f'"Authorization": "Bearer {bearer}"',
            f'"Cookie": "{cookie}"',
            f"unlabelled={jwt}",
            '"otp": 804271,',
            f"email={email}",
            f"PAYMENT_FIREWALL_ADMIN_SECRET={env_secret}",
        )
    )

    assert _scan(tmp_path, text) == {
        "JWT-like token",
        "OAuth bearer/access token",
        "cookie material",
        "email address",
        "one-time password",
        "sensitive environment assignment",
    }


def test_ignores_documentation_placeholders_and_test_fixtures(tmp_path: Path) -> None:
    dsn_key = "PAYMENT_FIREWALL_POSTGRES_" + "DSN"
    sample_dsn = (
        "postgresql://firewall_user:firewall_password@"
        + "localhost:5432/firewall"
    )
    text = """
Authorization: Bearer <access-token>
access_token = "replace-with-access-token"
refresh_token: ${OAUTH_REFRESH_TOKEN}
authorization_code: YOUR_AUTHORIZATION_CODE
receipt_token: "opaque-test-receipt"
X-Spend-Token: <spend-token>
Cookie: session=<session-id>
otp=123456
email=owner@example.com
PAYMENT_FIREWALL_ADMIN_SECRET=replace-with-local-admin-secret
demo_access_token="demo-team-token"
""" + f"\n{dsn_key}={sample_dsn}\n"

    assert _scan(tmp_path, text, name=".env.example") == set()


def test_ignores_runtime_variables_and_type_declarations(tmp_path: Path) -> None:
    text = """
access_token = token.json()["access_token"]
headers = {"Authorization": f"Bearer {access_token}"}
receipt_token = issue_receipt(payload)
spend_token = response.json()["spend_token"]
receipt_header = receiptResult.body.receipt_token
spend_token = raw_spend_token
x_spend_token = x_spend_token
email: str | None = None
PAYMENT_FIREWALL_ADMIN_SECRET = os.getenv("PAYMENT_FIREWALL_ADMIN_SECRET")
"""

    assert _scan(tmp_path, text, name="source.py") == set()
