# Branch-Coverage Report

**Status: PROVISIONAL — Windows measurement on an unintegrated branch**

## Measurement context

- Date: 2026-11-16
- Branch: `pps17-test-plan-traceability`
- Tested HEAD: `8f69bde2989c8b232f4d766ff46f53ddf9f7e9a0`
- `origin/main` at inspection: `198032cc1c8b91c7b7197ffee8fc5f89df0a0a33`
- Integration status: two commits ahead of `origin/main`; not integrated.
- OS: Windows 10, build 26200
- Python: 3.10.6
- Coverage.py: 7.16.2 (C extension)
- Branch measurement enabled with `coverage.Coverage(branch=True)`.
- Measured source scope: `dashboard.py`, `core`, and `services`.

Coverage was collected during the full test suite. The Python 3.10 run used a
process-local `datetime.UTC` compatibility alias. It reported 127 passed and
6 skipped; the skipped cases are listed in the
[Unit-Test Report](./unit-test-report.md).

## Result

- **292 of 398 branch arcs covered: 73.37%.**
- **106 branch arcs missed.**
- Coverage.py reported 84 partially covered branch points.

This is branch coverage only. It is not a statement of requirement coverage,
test-plan traceability, or system-test completion. The separate line result is
in the [Code-Coverage Report](./code-coverage-report.md).

## Per-module branch results

| Module | Covered branch arcs | Branch coverage |
|---|---:|---:|
| `core/types.py` | 0/0 | N/A |
| `dashboard.py` | 86/136 | 63.24% |
| `services/alert_service.py` | 14/16 | 87.50% |
| `services/capture_service.py` | 91/112 | 81.25% |
| `services/export_service.py` | 25/32 | 78.12% |
| `services/log_reader.py` | 36/42 | 85.71% |
| `services/session_index.py` | 29/46 | 63.04% |
| `services/summary_service.py` | 11/14 | 78.57% |

The empty package initializers contain no branch arcs and are not included in
the aggregate.

## Limitations and final rerun

These figures were measured on Windows, not the final Linux VM, and on a
branch that is not integrated into `main`. The prior Linux VM suite did not
collect coverage. Regenerate branch coverage on the final integrated commit
and Linux VM before treating this report as final.

If Coverage.py is available in the VM, run from the repository root:

```sh
/tmp/pps16-venv/bin/python -m coverage run \
  --branch --source=dashboard,core,services -m pytest -q -rs
/tmp/pps16-venv/bin/python -m coverage report -m
/tmp/pps16-venv/bin/python -m coverage json -o /tmp/pps19-coverage.json
```

First check `/tmp/pps16-venv/bin/python -m coverage --version`. If it is
missing, request approval before installing it; coverage.py was not part of
the existing pytest-only VM setup.
