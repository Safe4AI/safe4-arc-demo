from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_hash_token: Callable[[str], str] | None = None
_issue_secret_token: Callable[[str], tuple[str, str]] | None = None
_normalize_scope_string: Callable[[str], list[str]] | None = None
_verify_pkce: Callable[[str, str], bool] | None = None
_error_payload: Callable[[Request, str, str, dict[str, Any] | None], dict[str, Any]] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_allowed_scopes: set[str] = set()
_oauth_issuer = ""
_access_token_ttl_seconds = 0
_refresh_token_ttl_seconds = 0
_auth_code_ttl_seconds = 0


def compute_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def setup_oauth_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    hash_token: Callable[[str], str],
    issue_secret_token: Callable[[str], tuple[str, str]],
    normalize_scope_string: Callable[[str], list[str]],
    verify_pkce: Callable[[str, str], bool],
    error_payload: Callable[[Request, str, str, dict[str, Any] | None], dict[str, Any]],
    sanitize_text: Callable[[str, int], str],
    allowed_scopes: set[str],
    oauth_issuer: str,
    access_token_ttl_seconds: int,
    refresh_token_ttl_seconds: int,
    auth_code_ttl_seconds: int,
) -> None:
    global _store, _append_audit_entry, _hash_token, _issue_secret_token, _normalize_scope_string
    global _verify_pkce, _error_payload, _sanitize_text, _allowed_scopes, _oauth_issuer
    global _access_token_ttl_seconds, _refresh_token_ttl_seconds, _auth_code_ttl_seconds
    _store = store
    _append_audit_entry = append_audit_entry
    _hash_token = hash_token
    _issue_secret_token = issue_secret_token
    _normalize_scope_string = normalize_scope_string
    _verify_pkce = verify_pkce
    _error_payload = error_payload
    _sanitize_text = sanitize_text
    _allowed_scopes = allowed_scopes
    _oauth_issuer = oauth_issuer
    _access_token_ttl_seconds = access_token_ttl_seconds
    _refresh_token_ttl_seconds = refresh_token_ttl_seconds
    _auth_code_ttl_seconds = auth_code_ttl_seconds


class OAuthAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    client_id: str = Field(..., min_length=1)
    redirect_uri: str = Field(..., min_length=1)
    scope: str = Field(..., min_length=1)
    code_challenge: str = Field(..., min_length=43, max_length=128)
    code_challenge_method: str = Field(..., min_length=1)
    subject: str = Field(..., min_length=1)
    agent_id: str | None = Field(default=None)

    @field_validator("client_id", "redirect_uri", "subject", "agent_id")
    @classmethod
    def sanitize_text_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("field cannot be empty")
        return sanitized

    @field_validator("code_challenge_method")
    @classmethod
    def validate_code_challenge_method(cls, value: str) -> str:
        if value != "S256":
            raise ValueError("code_challenge_method must be S256")
        return value


class OAuthTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    grant_type: str = Field(..., min_length=1)
    client_id: str = Field(..., min_length=1)
    code: str | None = Field(default=None)
    redirect_uri: str | None = Field(default=None)
    code_verifier: str | None = Field(default=None)
    refresh_token: str | None = Field(default=None)

    @field_validator("client_id", "code", "redirect_uri", "code_verifier", "refresh_token")
    @classmethod
    def sanitize_token_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("field cannot be empty")
        return sanitized


class OAuthRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: str = Field(..., min_length=1)


@router.get("/.well-known/openid-configuration")
def openid_configuration() -> dict[str, Any]:
    return {
        "issuer": _oauth_issuer,
        "authorization_endpoint": f"{_oauth_issuer}/oauth/authorize",
        "token_endpoint": f"{_oauth_issuer}/oauth/token",
        "revocation_endpoint": f"{_oauth_issuer}/oauth/revoke",
        "scopes_supported": sorted(_allowed_scopes),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    }


@router.post("/oauth/authorize")
def oauth_authorize(request: Request, payload: OAuthAuthorizeRequest) -> JSONResponse:
    client = _store.get_oauth_client(payload.client_id)
    if client is None or not client["is_active"]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_payload(request, "INVALID_CLIENT", "OAuth client is not recognized."),
        )
    if payload.redirect_uri not in client["redirect_uris"]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_payload(request, "INVALID_REDIRECT_URI", "redirect_uri is not registered for this client."),
        )
    try:
        scopes = _normalize_scope_string(payload.scope)
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_payload(request, "INVALID_SCOPE", str(exc)),
        )
    if any(scope not in client["allowed_scopes"] for scope in scopes):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_payload(request, "INVALID_SCOPE", "Requested scopes exceed client permissions."),
        )

    authorization_code, code_hash = _issue_secret_token("ac")
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=_auth_code_ttl_seconds)).isoformat()
    _store.create_oauth_authorization_code(
        code_hash=code_hash,
        client_id=payload.client_id,
        subject=payload.subject,
        agent_id=payload.agent_id,
        redirect_uri=payload.redirect_uri,
        scopes=scopes,
        code_challenge=payload.code_challenge,
        code_challenge_method=payload.code_challenge_method,
        expires_at=expires_at,
    )
    _append_audit_entry(
        actor_type="user",
        actor_id=payload.subject,
        action="oauth_authorize",
        request_path="/oauth/authorize",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"client_id": payload.client_id, "scopes": scopes},
        decision="issued",
        decision_reason=None,
        decision_details={"grant_type": "authorization_code"},
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "code": authorization_code,
            "expires_at": expires_at,
            "scope": " ".join(scopes),
            "request_id": request.state.request_id,
        },
    )


@router.post("/oauth/token")
def oauth_token(request: Request, payload: OAuthTokenRequest) -> JSONResponse:
    client = _store.get_oauth_client(payload.client_id)
    if client is None or not client["is_active"]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_payload(request, "INVALID_CLIENT", "OAuth client is not recognized."),
        )

    if payload.grant_type == "authorization_code":
        if not payload.code or not payload.redirect_uri or not payload.code_verifier:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_REQUEST", "code, redirect_uri, and code_verifier are required."),
            )
        code_record = _store.consume_oauth_authorization_code(_hash_token(payload.code))
        if code_record is None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "Authorization code is invalid or already used."),
            )
        if code_record["client_id"] != payload.client_id or code_record["redirect_uri"] != payload.redirect_uri:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "Authorization code does not match this client request."),
            )
        if datetime.fromisoformat(code_record["expires_at"]) <= datetime.now(timezone.utc):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "Authorization code has expired."),
            )
        if not _verify_pkce(payload.code_verifier, code_record["code_challenge"]):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "PKCE verification failed."),
            )

        access_token, access_hash = _issue_secret_token("at")
        refresh_token, refresh_hash = _issue_secret_token("rt")
        access_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=_access_token_ttl_seconds)).isoformat()
        refresh_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=_refresh_token_ttl_seconds)).isoformat()
        _store.create_oauth_access_token(
            token_hash=access_hash,
            client_id=payload.client_id,
            subject=code_record["subject"],
            agent_id=code_record["agent_id"],
            scopes=code_record["scopes"],
            expires_at=access_expires_at,
        )
        _store.create_oauth_refresh_token(
            token_hash=refresh_hash,
            client_id=payload.client_id,
            subject=code_record["subject"],
            agent_id=code_record["agent_id"],
            scopes=code_record["scopes"],
            expires_at=refresh_expires_at,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": _access_token_ttl_seconds,
                "scope": " ".join(code_record["scopes"]),
            },
        )

    if payload.grant_type == "refresh_token":
        if not payload.refresh_token:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_REQUEST", "refresh_token is required."),
            )
        next_refresh_token, next_refresh_hash = _issue_secret_token("rt")
        refresh_record = _store.consume_oauth_refresh_token(_hash_token(payload.refresh_token), next_refresh_hash)
        if refresh_record is None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "Refresh token is invalid or already used."),
            )
        if refresh_record["client_id"] != payload.client_id:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "Refresh token does not belong to this client."),
            )
        if datetime.fromisoformat(refresh_record["expires_at"]) <= datetime.now(timezone.utc):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_error_payload(request, "INVALID_GRANT", "Refresh token has expired."),
            )
        access_token, access_hash = _issue_secret_token("at")
        access_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=_access_token_ttl_seconds)).isoformat()
        refresh_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=_refresh_token_ttl_seconds)).isoformat()
        _store.create_oauth_access_token(
            token_hash=access_hash,
            client_id=payload.client_id,
            subject=refresh_record["subject"],
            agent_id=refresh_record["agent_id"],
            scopes=refresh_record["scopes"],
            expires_at=access_expires_at,
        )
        _store.create_oauth_refresh_token(
            token_hash=next_refresh_hash,
            client_id=payload.client_id,
            subject=refresh_record["subject"],
            agent_id=refresh_record["agent_id"],
            scopes=refresh_record["scopes"],
            expires_at=refresh_expires_at,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": access_token,
                "refresh_token": next_refresh_token,
                "token_type": "Bearer",
                "expires_in": _access_token_ttl_seconds,
                "scope": " ".join(refresh_record["scopes"]),
            },
        )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=_error_payload(request, "UNSUPPORTED_GRANT_TYPE", "grant_type must be authorization_code or refresh_token."),
    )


@router.post("/oauth/revoke")
def oauth_revoke(request: Request, payload: OAuthRevokeRequest) -> JSONResponse:
    revoked = _store.revoke_oauth_token(_hash_token(payload.token))
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"revoked": revoked, "request_id": request.state.request_id},
    )
