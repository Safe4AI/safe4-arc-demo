from __future__ import annotations

import unittest

from decimal import Decimal

from app.ops import anomalies


class OpsPackageTests(unittest.TestCase):
    def test_anomaly_threshold_comparison(self) -> None:
        self.assertTrue(
            anomalies.anomaly_severity_meets_threshold(severity="high", threshold="medium")
        )
        self.assertFalse(
            anomalies.anomaly_severity_meets_threshold(severity="low", threshold="high")
        )

    def test_anomaly_score_constant_is_decimal(self) -> None:
        self.assertIsInstance(anomalies.INFRASTRUCTURE_IDENTITY_ANOMALY_NEW_CURRENCY_SCORE, Decimal)


if __name__ == "__main__":
    unittest.main()
