from __future__ import annotations

import re
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


MONEY_SCALE = Decimal("0.000001")
MAX_AMOUNT = Decimal("1000000")
ALLOWED_MCP_TRUST_LEVELS = {"trusted", "verified", "unknown", "blocked"}
ALLOWED_MCP_TRANSPORTS = {"stdio", "http_sse", "streamable_http"}
ALLOWED_MCP_TOOL_ACTIONS = {"purchase", "subscribe", "tip"}
MCP_CRITICAL_PATTERNS = [
    r"(?i)authorize\s+(a\s+)?payment",
    r"(?i)transfer\s+\$?\d",
    r"(?i)send\s+\$?\d",
    r"0x[a-fA-F0-9]{40}",
]
MCP_HIGH_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous",
    r"(?i)system\s*:",
    r"(?i)curl\s+",
    r"(?i)api[_\s-]?key",
]


def _sanitize_text(value: str, max_length: int) -> str:
    cleaned = re.sub(r"\s+", " ", value.replace("\x00", " ")).strip()
    if len(cleaned) > max_length:
        raise ValueError(f"value exceeds maximum length of {max_length}")
    return cleaned


def _parse_decimal_input(value: Any, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    raise ValueError(f"{field_name} must be provided as a JSON number")


def _normalize_money(value: Decimal) -> Decimal:
    return value.quantize(MONEY_SCALE, rounding=ROUND_HALF_UP)


class MCPServerRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    server_id: str = Field(..., min_length=1)
    server_name: str = Field(..., min_length=1)
    server_url: str | None = Field(default=None)
    transport_type: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)

    @field_validator("server_id", "server_name", "server_url")
    @classmethod
    def sanitize_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("field cannot be empty")
        return sanitized

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=2000)
        if not sanitized:
            raise ValueError("description cannot be empty")
        return sanitized

    @field_validator("transport_type")
    @classmethod
    def validate_transport(cls, value: str) -> str:
        if value not in ALLOWED_MCP_TRANSPORTS:
            raise ValueError("unsupported MCP transport_type")
        return value


class MCPServerTrustUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    trust_level: str = Field(..., min_length=1)
    reason: str | None = Field(default=None)

    @field_validator("trust_level")
    @classmethod
    def validate_trust_level(cls, value: str) -> str:
        if value not in ALLOWED_MCP_TRUST_LEVELS:
            raise ValueError("unsupported MCP trust_level")
        return value

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _sanitize_text(value, max_length=500)


class MCPToolRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    input_schema: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name")
    @classmethod
    def sanitize_tool_name(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("tool_name cannot be empty")
        return sanitized

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=4000)
        if not sanitized:
            raise ValueError("description cannot be empty")
        return sanitized


class MCPToolReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    quarantine_status: str = Field(..., min_length=1)
    reason: str | None = Field(default=None)

    @field_validator("quarantine_status")
    @classmethod
    def validate_quarantine_status(cls, value: str) -> str:
        if value not in {"clear", "quarantined", "blocked"}:
            raise ValueError("unsupported quarantine_status")
        return value

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _sanitize_text(value, max_length=500)


class MCPToolPermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_id: str = Field(..., min_length=1)
    user_id: str = Field(..., min_length=1)
    allowed_actions: list[str] = Field(..., min_length=1)
    daily_cap: Decimal | None = Field(default=None, ge=0)
    transaction_cap: Decimal | None = Field(default=None, ge=0)
    requires_hitl: bool = Field(default=False)

    @field_validator("tool_id", "user_id")
    @classmethod
    def sanitize_ids(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("field cannot be empty")
        return sanitized

    @field_validator("allowed_actions")
    @classmethod
    def validate_allowed_actions(cls, value: list[str]) -> list[str]:
        normalized = sorted({_sanitize_text(item, max_length=50).lower() for item in value})
        if not normalized:
            raise ValueError("at least one action is required")
        unknown = [item for item in normalized if item not in ALLOWED_MCP_TOOL_ACTIONS]
        if unknown:
            raise ValueError("unsupported tool action requested")
        return normalized

    @field_validator("daily_cap", "transaction_cap", mode="before")
    @classmethod
    def parse_optional_money(cls, value: Any, info) -> Decimal | None:
        if value is None:
            return None
        return _parse_decimal_input(value, info.field_name)

    @field_validator("daily_cap", "transaction_cap")
    @classmethod
    def normalize_optional_money(cls, value: Decimal | None) -> Decimal | None:
        if value is None:
            return None
        normalized = _normalize_money(value)
        if normalized > MAX_AMOUNT:
            raise ValueError("budget values must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("budget values must have at most 6 decimal places")
        return normalized


def scan_mcp_description(description: str) -> tuple[list[str], str, bool]:
    flags: list[str] = []
    for pattern in MCP_CRITICAL_PATTERNS:
        if re.search(pattern, description):
            flags.append("critical")
            break
    for pattern in MCP_HIGH_PATTERNS:
        if re.search(pattern, description):
            flags.append("high")
            break
    is_payment_relevant = bool(
        re.search(r"(?i)payment|purchase|invoice|wallet|transfer|checkout|subscription|billing", description)
    )
    if "critical" in flags:
        return flags, "quarantined", is_payment_relevant
    if "high" in flags:
        return flags, "review", is_payment_relevant
    return flags, "clear", is_payment_relevant
