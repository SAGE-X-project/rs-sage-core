"""Defensive checks for the test-only cross-language comparison parser."""
from pathlib import Path
import runpy
import unittest

HELPERS = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/check_did_record_views010.py"))

class StrictComparison(unittest.TestCase):
    def test_duplicate_members_and_non_json_constants_are_rejected(self):
        for value in ['{"id":"a","id":"b"}', '{"nested":{"x":1,"x":2}}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                HELPERS["strict_json"](value)

    def test_boolean_number_and_string_metadata_stay_distinct(self):
        values = [{"deactivated": False}, {"deactivated": 0}, {"deactivated": "false"}, {"deactivated": True}, {"deactivated": 1}]
        self.assertEqual(len({HELPERS["exact_json"](v) for v in values}), len(values))

    def test_object_order_does_not_hide_array_order_or_missing_members(self):
        self.assertEqual(HELPERS["exact_json"]({"a":1,"b":2}), HELPERS["exact_json"]({"b":2,"a":1}))
        self.assertNotEqual(HELPERS["exact_json"]({"keys":["a","b"]}), HELPERS["exact_json"]({"keys":["b","a"]}))
        self.assertNotEqual(HELPERS["exact_json"]({"service":[]}), HELPERS["exact_json"]({}))

if __name__ == "__main__":
    unittest.main()
