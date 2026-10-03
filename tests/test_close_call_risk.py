import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from close_call_agent import maker_quote_price, position_change_allowed


class CloseCallRiskTests(unittest.TestCase):
    def test_position_cap_is_strict_when_current_position_is_inside(self):
        self.assertTrue(position_change_allowed(-19.0, -20.0, 20.0))
        self.assertFalse(position_change_allowed(-19.0, -20.01, 20.0))

    def test_over_cap_only_allows_strictly_reducing_exposure(self):
        self.assertTrue(position_change_allowed(-42.48, -37.48, 20.0))
        self.assertFalse(position_change_allowed(-42.48, -47.48, 20.0))
        self.assertFalse(position_change_allowed(-42.48, -42.48, 20.0))

    def test_no_maker_quote_when_edge_price_is_outside_referee_band(self):
        # At a 234.77 reference with a 215.20 forecast, a profitable buy
        # would be below the official lower band, so it must not be quoted.
        self.assertIsNone(maker_quote_price("buy", 234.77, 223.04, 246.50, 215.20))

    def test_buy_quote_uses_profitable_limit_inside_band(self):
        quote = maker_quote_price("buy", 221.0, 209.95, 232.05, 215.20)
        self.assertIsNotNone(quote)
        price, edge = quote
        self.assertGreaterEqual(price, 209.95)
        self.assertLessEqual(price, 232.05)
        self.assertTrue(price <= 215.20 / 1.015)
        self.assertGreaterEqual(edge, 0.0)

    def test_sell_quote_uses_profitable_limit_inside_band(self):
        quote = maker_quote_price("sell", 220.0, 209.0, 231.0, 215.20)
        self.assertIsNotNone(quote)
        price, edge = quote
        self.assertGreaterEqual(price, 209.0)
        self.assertLessEqual(price, 231.0)
        self.assertTrue(price >= 215.20 / 0.985)
        self.assertGreaterEqual(edge, 0.0)


if __name__ == "__main__":
    unittest.main()