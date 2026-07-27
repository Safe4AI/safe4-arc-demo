from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app import main, webhooks_api
from app.api import audit, budgets, demo, hitl, integrations, oauth, ops, phase3, policy, receipts, webhooks
from app.integrations.range import reset_range_requester_for_tests


class ApiPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        main.reset_runtime_state()
        webhooks_api.reset_webhook_sender_for_tests()
        reset_range_requester_for_tests()

    def test_router_modules_export_router(self) -> None:
        for module in [audit, budgets, demo, hitl, integrations, oauth, ops, phase3, policy, receipts, webhooks]:
            self.assertTrue(hasattr(module, "router"))

    def test_health_endpoint_still_available(self) -> None:
        with TestClient(main.app) as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
