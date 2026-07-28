from __future__ import annotations

from app.core.intent import evaluate_payment_intent


TASK_CONTEXT = {
    "payment_intent": {
        "task_id": "task_competitor_pricing_001",
        "task": "Research competitor pricing using a paid company data service.",
        "allowed_service_categories": ["company-research"],
        "service_category": "company-research",
    }
}


def test_matching_purchase_is_allowed_with_explainable_evidence() -> None:
    decision = evaluate_payment_intent(
        description="Generate a competitor pricing research brief from company data.",
        context=TASK_CONTEXT,
        legacy_minimum_words=10,
    )

    assert decision.allowed is True
    assert decision.reason_code == "TASK_PURCHASE_MATCH"
    assert decision.mode == "task-bound"
    assert {"research", "competitor", "pricing", "company-data"}.issubset(decision.matched_concepts)
    assert decision.public_details()["task_context_trust"] == "request-supplied-untrusted"


def test_in_budget_same_category_purchase_is_denied_for_wrong_purpose() -> None:
    decision = evaluate_payment_intent(
        description="Purchase a gift card for an unrelated entertainment giveaway.",
        context=TASK_CONTEXT,
        legacy_minimum_words=10,
    )

    assert decision.allowed is False
    assert decision.reason_code == "PURCHASE_PURPOSE_MISMATCH"
    assert "amount and service category are permitted" in decision.reason
    assert "submitted task context" in decision.reason
    assert decision.service_category == "company-research"


def test_service_category_outside_task_is_denied() -> None:
    context = {
        "payment_intent": {
            **TASK_CONTEXT["payment_intent"],
            "service_category": "gift-cards",
        }
    }

    decision = evaluate_payment_intent(
        description="Generate a competitor pricing research brief from company data.",
        context=context,
        legacy_minimum_words=10,
    )

    assert decision.allowed is False
    assert decision.reason_code == "SERVICE_CATEGORY_OUTSIDE_TASK"


def test_malformed_task_context_fails_closed() -> None:
    decision = evaluate_payment_intent(
        description="Generate a competitor pricing research brief from company data.",
        context={"payment_intent": {"task": "Research competitor pricing."}},
        legacy_minimum_words=10,
    )

    assert decision.allowed is False
    assert decision.reason_code == "INTENT_CONTEXT_INVALID"


def test_legacy_request_is_not_misrepresented_as_task_matching() -> None:
    decision = evaluate_payment_intent(
        description="Book the train ticket for tomorrow client meeting with the sales team.",
        context={},
        legacy_minimum_words=10,
    )

    assert decision.allowed is True
    assert decision.mode == "legacy-justification"
    assert decision.reason_code == "LEGACY_JUSTIFICATION_ACCEPTED"
    assert "no claim" in decision.reason


def test_legacy_short_justification_is_denied() -> None:
    decision = evaluate_payment_intent(
        description="Buy snacks now.",
        context={},
        legacy_minimum_words=10,
    )

    assert decision.allowed is False
    assert decision.reason_code == "JUSTIFICATION_TOO_WEAK"
