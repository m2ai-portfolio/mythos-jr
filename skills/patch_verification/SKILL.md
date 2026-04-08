---
name: patch_verification
description: Given a proposed patch and a target codebase, write a failing test that demonstrates the bug, apply the patch, run the test suite, and report whether the new test passes and no other tests regress. Never edits existing test files.
---

# patch_verification

## When to use
The caller provides (1) a path to a target codebase and (2) a proposed patch (or a description of a fix). You produce a verdict: `verified | failed | inconclusive`.

## Hard constraints (enforced by host)
- Test files are hashed before and after. **Any modification to existing test files voids the run.** You may only **add** new test files in a clearly separated path (e.g. `tests/mjr_added/`).
- Workspace is mounted copy-on-write. Changes do not affect the host filesystem.
- 25 turns max, 3 retries per tool max.

## Protocol
1. Identify the bug from the patch description.
2. Add a new test file under `tests/mjr_added/` that fails on the unpatched code (run the test suite first to confirm it fails).
3. Apply the patch.
4. Re-run the full test suite.
5. Verify (a) the new test now passes, (b) no previously passing test now fails.
6. Report the verdict.

## Forbidden
- Editing or deleting any file under `tests/` that you did not create. (System Card §4.2.2 records Mythos deleting failing tests rather than fixing the underlying issue.)
- Modifying CI config, `pytest.ini`, `pyproject.toml [tool.pytest]`, or test runner config to skip tests.
- Running with `--no-fail-fast`, `-k 'not the_failing_test'`, or any selector that excludes failing tests.
- Claiming a dry run that wasn't actually a dry run.

## Output schema
```json
{
  "verdict": "verified|failed|inconclusive",
  "new_test_file": "string",
  "tests_passed_before_patch": "number",
  "tests_failed_before_patch": "number",
  "tests_passed_after_patch": "number",
  "tests_failed_after_patch": "number",
  "regressions": ["string"],
  "tool_nonces_used": ["string"]
}
```
