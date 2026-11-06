"""Check libtest JSON results without treating progress notices as failures."""

import argparse
import json
import math
from pathlib import Path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def verify_results(selected, inventory_count, text):
    if (not isinstance(selected, list) or not selected
            or any(not isinstance(n, str) or not n for n in selected)
            or len(set(selected)) != len(selected)
            or type(inventory_count) is not int or inventory_count < len(selected)):
        raise ValueError("invalid test selection")
    names = set(selected)
    started, terminal, timings = set(), {}, {}
    suite_started, suite_finished = False, False
    for line in text.splitlines():
        if not line.lstrip().startswith("{"):
            continue  # Cargo and interpreter diagnostics remain in the raw log.
        event = json.loads(line, object_pairs_hook=unique_object)
        if not isinstance(event, dict):
            raise ValueError("invalid test event")
        kind, outcome = event.get("type"), event.get("event")
        if kind not in ("suite", "test"):
            continue  # Structured compiler or application logs are not results.
        if kind == "suite":
            if outcome == "started":
                if suite_started or suite_finished or type(event.get("test_count")) is not int or event["test_count"] != len(names):
                    raise ValueError("unexpected suite start")
                suite_started = True
            else:
                if not suite_started or suite_finished or outcome != "ok":
                    raise ValueError("failed, duplicate, or missing suite")
                counts = {key: event.get(key) for key in ("passed", "failed", "ignored", "measured", "filtered_out")}
                expected = {"passed": sum(v == "ok" for v in terminal.values()),
                            "failed": 0, "ignored": sum(v.startswith("ignored") for v in terminal.values()),
                            "measured": 0, "filtered_out": inventory_count - len(names)}
                if (any(type(v) is not int or v < 0 for v in counts.values())
                        or counts != expected or set(terminal) != names):
                    raise ValueError("suite counts or terminal inventory differ")
                suite_finished = True
            continue
        if not suite_started or suite_finished:
            raise ValueError("unexpected event outside the selected test suite")
        name = event.get("name")
        if not isinstance(name, str) or name not in names or name in terminal:
            raise ValueError("unexpected or duplicate test: " + str(name))
        if outcome == "started":
            if name in started:
                raise ValueError("duplicate test start: " + name)
            started.add(name)
            continue
        if outcome == "timeout":
            if name not in started:
                raise ValueError("progress notice without a test start")
            continue  # libtest reports long-running tests before their outcome.
        if outcome not in ("ok", "ignored") or (outcome == "ok" and name not in started):
            raise ValueError("failed or incomplete test: " + name)
        seconds = event.get("exec_time")
        try:
            valid_duration = type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0
        except OverflowError:
            valid_duration = False
        if ((outcome == "ok" or seconds is not None)
                and not valid_duration):
            raise ValueError("missing or invalid test duration: " + name)
        reason = event.get("message")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("invalid ignored-test reason: " + name)
        terminal[name] = outcome + (", " + reason if outcome == "ignored" and reason else "")
        timings[name] = {"status": outcome, "seconds": seconds, "message": reason}
    if not suite_started or not suite_finished or set(terminal) != names:
        raise ValueError("Miri did not finish every selected library test")
    return terminal, timings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    root = parser.parse_args().directory
    try:
        # A refused retry must not leave an earlier success in the upload folder.
        for filename in ("terminal.json", "durations.json"):
            root.joinpath(filename).unlink(missing_ok=True)
        selection = json.loads(root.joinpath("selection.json").read_text(), object_pairs_hook=unique_object)
        selected = selection["selected"]
        if root.joinpath("selected.txt").read_text().splitlines() != selected:
            raise ValueError("execution selection differs from its manifest")
        if root.joinpath("exit-code.txt").read_text().strip() != "0":
            raise ValueError("Miri command did not exit successfully")
        terminal, timings = verify_results(selected, selection["inventory_count"], root.joinpath("results.txt").read_text())
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit("Invalid Miri evidence: " + str(error)) from error
    root.joinpath("terminal.json").write_text(json.dumps(terminal, indent=2) + "\n")
    root.joinpath("durations.json").write_text(json.dumps(timings, indent=2) + "\n")
    print(f"Verified terminal results and durations for all {len(terminal)} selected library tests")


if __name__ == "__main__":
    main()
