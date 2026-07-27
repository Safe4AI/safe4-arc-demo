from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app import main, webhooks_api
from app.api import demo
from app.api.demo import setup_demo_api
from app.integrations.range import reset_range_requester_for_tests


class DemoPageTests(unittest.TestCase):
    def setUp(self) -> None:
        main.reset_runtime_state()
        webhooks_api.reset_webhook_sender_for_tests()
        reset_range_requester_for_tests()
        setup_demo_api(demo_access_token="demo-team-token")

    def test_demo_module_exports_router(self) -> None:
        self.assertTrue(hasattr(demo, "router"))

    def test_demo_page_is_served(self) -> None:
        with TestClient(main.app) as client:
            response = client.get("/demo/agent-security?access_token=demo-team-token")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Safe4 Agent Security Gateway", response.text)
        self.assertIn("/pay", response.text)
        self.assertIn("Range Risk", response.text)

    def test_console_mock_page_is_served(self) -> None:
        with TestClient(main.app) as client:
            response = client.get("/demo/console?access_token=demo-team-token")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Safe4 Console Mockup", response.text)
        self.assertIn("Authorized Travel Purchase", response.text)
        self.assertIn("Blocked High-Risk Transfer", response.text)
        self.assertIn("Live Safe4 Signals", response.text)

    def test_demo_pages_are_hidden_without_access_token(self) -> None:
        with TestClient(main.app) as client:
            landing_response = client.get("/demo/agent-security")
            console_response = client.get("/demo/console")
        self.assertEqual(landing_response.status_code, 404)
        self.assertEqual(console_response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
