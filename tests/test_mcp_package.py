from __future__ import annotations

import unittest

from app.mcp import api, models, payment_policy


class McpPackageTests(unittest.TestCase):
    def test_mcp_modules_import(self) -> None:
        self.assertTrue(hasattr(api, "router"))
        self.assertTrue(hasattr(models, "MCPServerRegistrationRequest"))
        self.assertTrue(hasattr(payment_policy, "enforce_mcp_payment_policy"))


if __name__ == "__main__":
    unittest.main()
