# Code-Coverage Report

**Status: PROVISIONAL — Windows measurement on an unintegrated branch**

## Measurement context

- Date: 2026-11-16
- Branch: `pps17-test-plan-traceability`
- Tested HEAD: `8f69bde2989c8b232f4d766ff46f53ddf9f7e9a0`
- `origin/main` at inspection: `198032cc1c8b91c7b7197ffee8fc5f89df0a0a33`
- Integration status: two commits ahead of `origin/main`; not integrated.
- OS: Windows 10, build 26200
- Python: 3.10.6
- pytest: 9.1.1
- Coverage.py: 7.16.2 (C extension)
- Source scope: `dashboard.py`, `core`, and `services`; test files were not
  included in the measured source scope.

Coverage.py was already installed on this Windows host; no packages were
installed. The repository's CI workflow does not currently install or run
coverage. The Linux VM's Coverage.py availability has not been checked.

## Method and result

Coverage.py was started with `branch=True`; pytest ran in the same process.
Because this host's Python 3.10 lacks `datetime.UTC`, the run applied the
same process-local compatibility alias used for the Windows test run. This
shim did not modify repository files.

```powershell
@'
import datetime
import os
import tempfile
import coverage
import pytest

datetime.UTC = datetime.timezone.utc
data_path = os.path.join(tempfile.gettempdir(), 'pps19-coverage-8f69bde')
cov = coverage.Coverage(
    data_file=data_path,
    branch=True,
    source=['dashboard', 'core', 'services'],
)
cov.start()
exit_code = pytest.main(['-q'])
cov.stop()
cov.save()
print(f'COVERAGE_DATA={data_path}')
print(f'PYTEST_EXIT_CODE={exit_code}')
raise SystemExit(exit_code)
'@ | python -

python -m coverage report --data-file "$env:TEMP\pps19-coverage-8f69bde" --show-missing
python -m coverage json --data-file "$env:TEMP\pps19-coverage-8f69bde" `
  --pretty-print -o "$env:TEMP\pps19-coverage-8f69bde.json"
```

Coverage run result: **127 passed, 6 skipped, 0 failed** in 41.83 seconds.
The coverage data and JSON were written under the Windows temporary directory,
not into the repository.

Separate coverage figures were calculated from the Coverage.py JSON totals:

- **Line coverage:** 1,023 of 1,224 executable statements = **83.58%**
  (201 statements missed).
- **Branch coverage:** 292 of 398 branch arcs = **73.37%**
  (106 branch arcs missed).

Coverage.py's combined `Cover` column displays 81%; it combines statement and
branch opportunities. The line and branch percentages above are reported
separately from `percent_statements_covered` and `percent_branches_covered`
in the JSON output.

The first attempt to display the report used an unsupported `coverage report
--branch` option and exited with an option error. Branch measurement had
already been enabled during collection; rerunning `coverage report
--show-missing` and generating JSON succeeded.

## Per-module results

| Module | Lines covered | Line coverage | Branches covered | Branch coverage |
|---|---:|---:|---:|---:|
| `core/types.py` | 26/26 | 100.00% | 0/0 | N/A |
| `dashboard.py` | 260/336 | 77.38% | 86/136 | 63.24% |
| `services/alert_service.py` | 57/61 | 93.44% | 14/16 | 87.50% |
| `services/capture_service.py` | 323/388 | 83.25% | 91/112 | 81.25% |
| `services/export_service.py` | 58/69 | 84.06% | 25/32 | 78.12% |
| `services/log_reader.py` | 119/137 | 86.86% | 36/42 | 85.71% |
| `services/session_index.py` | 128/149 | 85.91% | 29/46 | 63.04% |
| `services/summary_service.py` | 52/58 | 89.66% | 11/14 | 78.57% |

Package `__init__.py` files contain no executable statements and no branches;
they do not affect the aggregate counts.

## Limitations

- This measures the Windows/Python 3.10 compatibility-shim run, not the
  project's final Linux VM environment.
- The Linux VM full-suite result of 133 passed is prior evidence from
  `c3c4492`; no Linux coverage result exists in the inspected evidence.
- The source and test code were unchanged between `c3c4492` and this
  documentation commit, but coverage remains provisional until regenerated
  against the final integrated revision and target VM.
- If Coverage.py is missing in the Linux VM, do not install it without
  approval. Check it with `python3.12 -m coverage --version` first.

## Required Linux VM rerun

After integration, verify the VM checkout is clean and on the final revision.
If Coverage.py is already available in the existing Python 3.12 environment,
run:

```sh
/tmp/pps16-venv/bin/python -m coverage run \
  --branch --source=dashboard,core,services -m pytest -q -rs
/tmp/pps16-venv/bin/python -m coverage report -m
/tmp/pps16-venv/bin/python -m coverage json -o /tmp/pps19-coverage.json
/tmp/pps16-venv/bin/python -c \
  "import json; d=json.load(open('/tmp/pps19-coverage.json')); t=d['totals']; print('line', t['covered_lines'], '/', t['num_statements'], t['percent_statements_covered']); print('branch', t['covered_branches'], '/', t['num_branches'], t['percent_branches_covered'])"
```

The JSON command reports statement and branch percentages separately. If
`python -m coverage --version` is unavailable in the VM, stop and request
approval before installing Coverage.py.
