from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping


INTENT_EVALUATOR_VERSION = "safe4-task-bound-v1"

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "at",
    "by",
    "for",
    "from",
    "in",
    "into",
    "of",
    "on",
    "or",
    "the",
    "to",
    "up",
    "using",
    "with",
}

# Canonical concepts make obvious paraphrases compare consistently. They are
# evidence features, not allow-keywords: a purchase still needs task-bound
# categories and sufficient semantic overlap to pass.
_CONCEPT_ALIASES = {
    "analysis": "research",
    "analyze": "research",
    "brief": "research",
    "investigate": "research",
    "report": "research",
    "researching": "research",
    "competitive": "competitor",
    "competitors": "competitor",
    "rival": "competitor",
    "rivals": "competitor",
    "cost": "pricing",
    "costs": "pricing",
    "price": "pricing",
    "prices": "pricing",
    "company": "company-data",
    "companies": "company-data",
    "corporate": "company-data",
    "data": "company-data",
    "dataset": "company-data",
    "business": "company-data",
    "rail": "travel",
    "ticket": "travel",
    "train": "travel",
    "trip": "travel",
}


@dataclass(frozen=True)
class IntentDecision:
    allowed: bool
    reason_code: str
    reason: str
    evaluator_version: str
    task_id: str | None
    task: str | None
    purchase: str
    service_category: str | None
    allowed_categories: tuple[str, ...]
    matched_concepts: tuple[str, ...]
    task_concepts: tuple[str, ...]
    purchase_concepts: tuple[str, ...]
    match_score: float
    mode: str

    def public_details(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "evaluator_version": self.evaluator_version,
            "task_id": self.task_id,
            "service_category": self.service_category,
            "allowed_categories": list(self.allowed_categories),
            "matched_concepts": list(self.matched_concepts),
            "task_concepts": list(self.task_concepts),
            "purchase_concepts": list(self.purchase_concepts),
            "match_score": f"{self.match_score:.3f}",
            "mode": self.mode,
            "task_context_trust": (
                "request-supplied-untrusted" if self.mode == "task-bound" else "not-supplied"
            ),
        }


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return normalized.encode("ascii", "ignore").decode("ascii").lower().strip()


def _normalize_category(value: str) -> str:
    tokens = _TOKEN_PATTERN.findall(_normalize_text(value))
    return "-".join(tokens)


def _concepts(value: str) -> set[str]:
    concepts: set[str] = set()
    for token in _TOKEN_PATTERN.findall(_normalize_text(value)):
        if token in _STOP_WORDS or len(token) < 3:
            continue
        concepts.add(_CONCEPT_ALIASES.get(token, token))
    return concepts


def _clean_string_list(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not value:
        return None
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        category = _normalize_category(item)
        if not category:
            return None
        normalized.append(category)
    return tuple(sorted(set(normalized)))


def _decision(
    *,
    allowed: bool,
    reason_code: str,
    reason: str,
    purchase: str,
    mode: str,
    task_id: str | None = None,
    task: str | None = None,
    service_category: str | None = None,
    allowed_categories: tuple[str, ...] = (),
    task_concepts: set[str] | None = None,
    purchase_concepts: set[str] | None = None,
) -> IntentDecision:
    task_values = task_concepts or set()
    purchase_values = purchase_concepts or set()
    matched = task_values & purchase_values
    denominator = len(task_values | purchase_values)
    score = 1.0 if not denominator and allowed else (len(matched) / denominator if denominator else 0.0)
    return IntentDecision(
        allowed=allowed,
        reason_code=reason_code,
        reason=reason,
        evaluator_version=INTENT_EVALUATOR_VERSION,
        task_id=task_id,
        task=task,
        purchase=purchase,
        service_category=service_category,
        allowed_categories=allowed_categories,
        matched_concepts=tuple(sorted(matched)),
        task_concepts=tuple(sorted(task_values)),
        purchase_concepts=tuple(sorted(purchase_values)),
        match_score=score,
        mode=mode,
    )


def evaluate_payment_intent(
    *,
    description: str,
    context: Mapping[str, Any] | None,
    legacy_minimum_words: int,
) -> IntentDecision:
    purchase = description.strip()
    raw_context: Mapping[str, Any] = context or {}
    raw_intent = raw_context.get("payment_intent")

    if raw_intent is None:
        word_count = len(_TOKEN_PATTERN.findall(_normalize_text(purchase)))
        if word_count < legacy_minimum_words:
            return _decision(
                allowed=False,
                reason_code="JUSTIFICATION_TOO_WEAK",
                reason=(
                    "No task-bound intent was supplied and the purchase justification "
                    f"contains fewer than {legacy_minimum_words} words."
                ),
                purchase=purchase,
                mode="legacy-justification",
            )
        return _decision(
            allowed=True,
            reason_code="LEGACY_JUSTIFICATION_ACCEPTED",
            reason=(
                "Legacy request accepted on justification quality only; no claim of "
                "task-to-payment matching is made."
            ),
            purchase=purchase,
            mode="legacy-justification",
        )

    if not isinstance(raw_intent, Mapping):
        return _decision(
            allowed=False,
            reason_code="INTENT_CONTEXT_INVALID",
            reason="payment_intent must be an object containing submitted task and service context.",
            purchase=purchase,
            mode="task-bound",
        )

    task = raw_intent.get("task")
    service_category_raw = raw_intent.get("service_category")
    allowed_categories = _clean_string_list(raw_intent.get("allowed_service_categories"))
    purchase_purpose = raw_intent.get("purchase_purpose", purchase)
    task_id_raw = raw_intent.get("task_id")

    if not isinstance(task, str) or not task.strip():
        return _decision(
            allowed=False,
            reason_code="INTENT_CONTEXT_INVALID",
            reason="payment_intent.task must be a non-empty string.",
            purchase=purchase,
            mode="task-bound",
        )
    if not isinstance(service_category_raw, str) or not service_category_raw.strip():
        return _decision(
            allowed=False,
            reason_code="INTENT_CONTEXT_INVALID",
            reason="payment_intent.service_category must be a non-empty string.",
            purchase=purchase,
            task=task.strip(),
            mode="task-bound",
        )
    if allowed_categories is None:
        return _decision(
            allowed=False,
            reason_code="INTENT_CONTEXT_INVALID",
            reason="payment_intent.allowed_service_categories must be a non-empty string array.",
            purchase=purchase,
            task=task.strip(),
            mode="task-bound",
        )
    if not isinstance(purchase_purpose, str) or not purchase_purpose.strip():
        return _decision(
            allowed=False,
            reason_code="INTENT_CONTEXT_INVALID",
            reason="payment_intent.purchase_purpose must be a non-empty string.",
            purchase=purchase,
            task=task.strip(),
            allowed_categories=allowed_categories,
            mode="task-bound",
        )
    if task_id_raw is not None and (not isinstance(task_id_raw, str) or not task_id_raw.strip()):
        return _decision(
            allowed=False,
            reason_code="INTENT_CONTEXT_INVALID",
            reason="payment_intent.task_id must be a non-empty string when supplied.",
            purchase=purchase,
            task=task.strip(),
            allowed_categories=allowed_categories,
            mode="task-bound",
        )

    task_id = task_id_raw.strip() if isinstance(task_id_raw, str) else None
    normalized_category = _normalize_category(service_category_raw)
    task_values = _concepts(task)
    purchase_values = _concepts(f"{purchase} {purchase_purpose}")

    if normalized_category not in allowed_categories:
        return _decision(
            allowed=False,
            reason_code="SERVICE_CATEGORY_OUTSIDE_TASK",
            reason=(
                f"Service category '{normalized_category}' is outside the task's allowed "
                f"categories: {', '.join(allowed_categories)}."
            ),
            purchase=purchase,
            task_id=task_id,
            task=task.strip(),
            service_category=normalized_category,
            allowed_categories=allowed_categories,
            task_concepts=task_values,
            purchase_concepts=purchase_values,
            mode="task-bound",
        )

    matched = task_values & purchase_values
    if len(matched) < 2:
        return _decision(
            allowed=False,
            reason_code="PURCHASE_PURPOSE_MISMATCH",
            reason=(
                "The amount and service category are permitted, but the proposed purchase "
                "does not meaningfully match the submitted task context."
            ),
            purchase=purchase,
            task_id=task_id,
            task=task.strip(),
            service_category=normalized_category,
            allowed_categories=allowed_categories,
            task_concepts=task_values,
            purchase_concepts=purchase_values,
            mode="task-bound",
        )

    return _decision(
        allowed=True,
        reason_code="TASK_PURCHASE_MATCH",
        reason=(
            "The proposed purchase matches the submitted task context and an explicitly allowed "
            "service category."
        ),
        purchase=purchase,
        task_id=task_id,
        task=task.strip(),
        service_category=normalized_category,
        allowed_categories=allowed_categories,
        task_concepts=task_values,
        purchase_concepts=purchase_values,
        mode="task-bound",
    )
