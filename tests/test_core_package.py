from __future__ import annotations

from decimal import Decimal
import unittest

from app.core import config


class CoreConfigTests(unittest.TestCase):
    def test_normalize_money_quantizes(self) -> None:
        self.assertEqual(config.normalize_money(Decimal("1.2345674")), Decimal("1.234567"))

    def test_parse_budget_alert_threshold_values_from_list(self) -> None:
        values = config.parse_budget_alert_threshold_values([0.5, 0.8, 1.0])
        self.assertEqual(values, [Decimal("0.500000"), Decimal("0.800000"), Decimal("1.000000")])


if __name__ == "__main__":
    unittest.main()
