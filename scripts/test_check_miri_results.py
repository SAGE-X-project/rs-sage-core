import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_miri_results import verify_results


def complete_events():
    return [
        {"type": "suite", "event": "started", "test_count": 2},
        {"type": "test", "event": "started", "name": "slow"},
        {"type": "test", "event": "timeout", "name": "slow"},
        {"type": "test", "event": "ok", "name": "slow", "exec_time": 1934.72},
        {"type": "test", "event": "ignored", "name": "native", "message": "requires directory synchronization"},
        {"type": "suite", "event": "ok", "passed": 1, "failed": 0,
         "ignored": 1, "measured": 0, "filtered_out": 654},
    ]


def render(events):
    return "cargo diagnostics\n" + "\n".join(json.dumps(event) for event in events)


class ResultTests(unittest.TestCase):
    def check(self, events):
        return verify_results(["slow", "native"], 656, render(events))

    def test_progress_is_not_a_failure_and_ignored_reason_is_retained(self):
        terminal, timings = self.check(complete_events())
        self.assertEqual(terminal, {"slow": "ok", "native": "ignored, requires directory synchronization"})
        self.assertEqual(timings["slow"]["seconds"], 1934.72)
        self.assertIsNone(timings["native"]["seconds"])

    def test_incomplete_or_inconsistent_logs_are_rejected(self):
        cases = []
        original = complete_events()
        for index in (0, 1, 3, 4, 5):
            cases.append(original[:index] + original[index + 1:])
        for index in (0, 1, 3, 4, 5):
            cases.append(original[:index] + [original[index]] + original[index:])
        for field, value in (("name", "unknown"), ("event", "failed"),
                             ("exec_time", -1), ("exec_time", True),
                             ("exec_time", float("nan")), ("exec_time", float("inf"))):
            events = copy.deepcopy(original)
            events[3][field] = value
            cases.append(events)
        for field, value in (("passed", 2), ("failed", 1), ("ignored", True),
                             ("filtered_out", 655), ("measured", 1), ("event", "failed")):
            events = copy.deepcopy(original)
            events[-1][field] = value
            cases.append(events)
        for events in cases:
            with self.subTest(events=events), self.assertRaises(ValueError):
                self.check(events)

    def test_duplicate_keys_and_invalid_json_are_rejected(self):
        for line in ('{"type":"suite","type":"test"}', '{"type":'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                verify_results(["slow", "native"], 656, line)

    def test_structured_diagnostics_cannot_supply_a_test_outcome(self):
        diagnostic = {"level": "INFO", "name": "slow", "event": "ok"}
        events = complete_events()
        self.check([diagnostic] + events)
        events[3] = diagnostic
        with self.assertRaises(ValueError):
            self.check(events)

    def test_invalid_selections_are_rejected(self):
        for selected, count in (([], 656), (["slow", "slow"], 656), (["slow"], True),
                                (["slow", "native"], 1), ([""], 656), ("abc", 656)):
            with self.subTest(selected=selected, count=count), self.assertRaises(ValueError):
                verify_results(selected, count, render(complete_events()))

    def test_command_writes_completed_evidence_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("selection.json").write_text(json.dumps({"selected": ["slow", "native"], "inventory_count": 656}))
            root.joinpath("selected.txt").write_text("slow\nnative\n")
            root.joinpath("exit-code.txt").write_text("0\n")
            root.joinpath("results.txt").write_text(render(complete_events()))
            command = [sys.executable, str(Path(__file__).with_name("check_miri_results.py")), directory]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(root.joinpath("durations.json").read_text())["slow"]["seconds"], 1934.72)
            for filename, value in (("selected.txt", "native\nslow\n"), ("exit-code.txt", "1\n")):
                for output in ("terminal.json", "durations.json"):
                    root.joinpath(output).write_text("stale success")
                old = root.joinpath(filename).read_text()
                root.joinpath(filename).write_text(value)
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(root.joinpath("terminal.json").exists())
                self.assertFalse(root.joinpath("durations.json").exists())
                root.joinpath(filename).write_text(old)


if __name__ == "__main__":
    unittest.main()
