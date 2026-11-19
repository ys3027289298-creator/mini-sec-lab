#!/usr/bin/env python3
"""run_checks.py — security-invariant checker for mini-sec-lab.

The checker is component-agnostic: every component exposes the same JSONL
driver protocol, so this file contains zero component-specific logic. Adding
a new component only needs a driver plus a key in invariants.json; adding a
new case only needs dropping a manifest under cases/<component>/.

Each case manifest:
  {
    "case": "<name>",
    "component": "<component>",
    "invariant": "<invariant id from invariants.json>",
    "steps": [
      {"id": "<optional>", "send": {...driver request...},
       "expect": {<subset the driver reply must match>}}
    ]
  }

String values in "send" starting with "$" are references to a previous
step's reply field, e.g. "$built.token".

Every case runs in its own driver subprocess: a crash, timeout or failed
assertion in one case never stops the remaining cases.
"""
import json
import selectors
import subprocess
import sys
from pathlib import Path

CHECKER_DIR = Path(__file__).resolve().parent
ROOT = CHECKER_DIR.parent
CASES_DIR = CHECKER_DIR / "cases"
CATALOG_PATH = CHECKER_DIR / "invariants.json"
DRIVER_TIMEOUT = 10  # seconds per case


class CaseFailure(Exception):
    """A violated invariant or a broken case/driver; never aborts the run."""


def load_catalog():
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    for component, invariants in catalog.items():
        if not isinstance(invariants, dict) or not invariants:
            raise SystemExit(f"invariants.json: component {component!r} has no invariants")
        for inv_id, spec in invariants.items():
            if spec.get("kind") not in ("accept", "reject"):
                raise SystemExit(f"invariants.json: {component}/{inv_id} has bad kind")
            if spec["kind"] == "reject" and "status" not in spec:
                raise SystemExit(f"invariants.json: reject invariant {component}/{inv_id} needs status")
            if "description" not in spec:
                raise SystemExit(f"invariants.json: {component}/{inv_id} needs description")
    return catalog


def resolve_refs(value, replies):
    """Replace "$step.field" strings with values captured from earlier replies."""
    if isinstance(value, str) and value.startswith("$"):
        step_id, _, field = value[1:].partition(".")
        if step_id not in replies:
            raise CaseFailure(f"reference {value!r} points at an unknown or later step")
        if field not in replies[step_id]:
            raise CaseFailure(f"reference {value!r}: field {field!r} absent from step reply "
                              f"{sorted(replies[step_id])}")
        return replies[step_id][field]
    if isinstance(value, dict):
        return {k: resolve_refs(v, replies) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_refs(v, replies) for v in value]
    return value


def match_expect(reply, expect):
    """A reply passes when it contains every expected key with an equal value."""
    mismatches = []
    for key, want in expect.items():
        if key not in reply:
            mismatches.append(f"field {key!r} missing (want {want!r})")
        elif reply[key] != want:
            mismatches.append(f"field {key!r} = {reply[key]!r}, want {want!r}")
    return mismatches


def run_case(manifest_path, catalog):
    """Execute one case in a fresh driver subprocess. Returns (ok, detail)."""
    component = manifest_path.parent.name
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        name = manifest["case"]
        if manifest.get("component") != component:
            raise CaseFailure(f"manifest component {manifest.get('component')!r} != directory "
                              f"{component!r}")
        inv_id = manifest["invariant"]
        if inv_id not in catalog[component]:
            raise CaseFailure(f"unknown invariant {inv_id!r} for component {component!r}")
        steps = manifest["steps"]
        if not steps:
            raise CaseFailure("case has no steps")
    except KeyError as e:
        return False, f"malformed manifest: missing key {e}"
    except json.JSONDecodeError as e:
        return False, f"malformed manifest JSON: {e}"
    except CaseFailure as e:
        return False, str(e)

    driver = CHECKER_DIR / f"{component}_drv"
    if not driver.exists():
        return False, f"driver {driver.name} not built; run make in checker/ first"

    invariant = catalog[component][inv_id]
    replies = {}
    seen_ids = set()
    for step in steps:
        if "id" in step and step["id"] in seen_ids:
            return False, f"duplicate step id {step['id']!r}"
        seen_ids.add(step.get("id"))

    # One persistent driver process per case; state (e.g. replay cache) lives
    # inside it and dies with it, so cases can never contaminate each other.
    try:
        proc = subprocess.Popen(
            [str(driver)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as e:
        return False, f"cannot start driver {driver.name}: {e}"

    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)

    def stop_driver():
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=DRIVER_TIMEOUT)
        selector.close()

    try:
        for i, step in enumerate(steps, 1):
            try:
                send = resolve_refs(step["send"], replies)
            except CaseFailure as e:
                stop_driver()
                return False, str(e)

            try:
                proc.stdin.write(json.dumps(send) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                stop_driver()
                return False, f"driver died before step {i} (exit {proc.returncode})"

            if not selector.select(timeout=DRIVER_TIMEOUT):
                stop_driver()
                return False, f"step {i}: driver timed out after {DRIVER_TIMEOUT}s"
            line = proc.stdout.readline()
            if line == "":
                stop_driver()
                return False, f"step {i}: driver closed stdout (exit {proc.returncode})"

            try:
                reply = json.loads(line)
            except json.JSONDecodeError:
                stop_driver()
                return False, f"step {i}: driver reply is not JSON: {line[:200]!r}"
            if "id" in step:
                replies[step["id"]] = reply

            expect = step.get("expect")
            if expect is None:
                continue
            mismatches = match_expect(reply, expect)
            if mismatches:
                stop_driver()
                kind = "accept" if invariant["kind"] == "accept" else "reject"
                return (
                    False,
                    f"violated invariant {inv_id} ({kind}): {invariant['description']}\n"
                    f"  step {i} send    : {json.dumps(send, ensure_ascii=False)}\n"
                    f"  step {i} expect  : {json.dumps(expect, ensure_ascii=False)}\n"
                    f"  step {i} reply   : {json.dumps(reply, ensure_ascii=False)}\n"
                    f"  mismatches       : {'; '.join(mismatches)}",
                )

        proc.stdin.close()
        if proc.wait(timeout=DRIVER_TIMEOUT) != 0:
            stderr = proc.stderr.read().strip()
            selector.close()
            return False, ("driver exited non-zero"
                           + (f"; stderr: {stderr[:300]}" if stderr else ""))
        selector.close()
    except Exception as e:  # driver misbehavior must not abort the whole run
        stop_driver()
        return False, f"driver error: {e!r}"
    return True, inv_id


def main():
    catalog = load_catalog()
    manifests = sorted(CASES_DIR.glob("*/*.json"), key=lambda p: (p.parent.name, p.name))
    if not manifests:
        print("no case manifests found", file=sys.stderr)
        return 2

    used = {component: set() for component in catalog}
    total = passed = 0
    failures = []

    for path in manifests:
        total += 1
        ok, detail = run_case(path, catalog)
        component = path.parent.name
        label = f"[{component}] {path.stem}"
        if ok:
            passed += 1
            used.setdefault(component, set()).add(detail)
            print(f"PASS {label}  invariant={detail}")
        else:
            failures.append((label, detail))
            print(f"FAIL {label}")
            for line in detail.splitlines():
                print(f"     {line}")

    print()
    print("---- invariant coverage ----")
    for component, invariants in catalog.items():
        component_used = used.get(component, set())
        for inv_id in sorted(invariants):
            mark = "exercised" if inv_id in component_used else "NO CASE"
            print(f"  {component}/{inv_id}: {mark}")

    print()
    print(f"---- summary: {total} cases, {passed} passed, {len(failures)} failed ----")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
