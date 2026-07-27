from __future__ import annotations

import unittest

from app.protocols import ap2, x402


class ProtocolPackageTests(unittest.TestCase):
    def test_protocol_modules_import(self) -> None:
        self.assertTrue(hasattr(ap2, "router"))
        self.assertTrue(hasattr(x402, "router"))
        self.assertTrue(hasattr(ap2, "enforce_ap2_policy"))
        self.assertTrue(hasattr(x402, "verify_x402_receipt"))


if __name__ == "__main__":
    unittest.main()
