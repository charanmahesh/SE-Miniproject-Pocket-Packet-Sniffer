# Unit-Test Report

**Status: PROVISIONAL — not the final integrated release report**

## Tested revision and environment

- Date: 2026-11-16
- Branch: `pps17-test-plan-traceability`
- Tested HEAD: `8f69bde2989c8b232f4d766ff46f53ddf9f7e9a0`
- `origin/main` at inspection: `198032cc1c8b91c7b7197ffee8fc5f89df0a0a33`
- Integration status: the worktree was clean; this branch is two commits ahead
  of `origin/main` and is not integrated.
- Test host: Windows 10, build 26200
- Python: 3.10.6
- pytest: 9.1.1
- The project CI workflow uses Python 3.12 and installs pytest; it does not
  configure coverage. See `.github/workflows/tests.yml`.

The current environment is Windows, while the project's final demonstration
target is a Linux VM. These Windows results are supplementary and do not
replace running the suite on the Linux VM at the tested revision.

## Commands and results

### Native full-suite invocation

Command:

```powershell
python -m pytest -q
```

Result: **collection failed; 0 tests ran**. `tests/test_dashboard.py` imports
`datetime.UTC`, which is unavailable in Python 3.10.6. pytest exited with code
2. This is an environment/version incompatibility, not a reported test
assertion failure.

### Windows compatibility-shim invocation

To collect the suite on this host, the process temporarily aliased
`datetime.UTC` to `datetime.timezone.utc`. No repository files were changed by
the shim.

Command executed from PowerShell:

```powershell
@'
import datetime
import platform
import pytest
print('PYTHON', platform.python_version())
print('OS', platform.platform())
datetime.UTC = datetime.timezone.utc
raise SystemExit(pytest.main(['-q', '-rs']))
'@ | python -
```

Result: **127 passed, 6 skipped, 0 failed** in 5.00 seconds.

Skipped tests:

| Test(s) | Reason |
|---|---|
| `tests/test_export_service.py::test_exported_files_are_owner_only_on_posix` | POSIX mode bits are not portable to Windows. |
| `test_symlink_destination_is_rejected_without_writing_through_it`, `test_symlinked_source_is_rejected_without_copying_its_target`, `test_symlink_at_export_filename_is_not_followed_or_overwritten` in `tests/test_export_service.py` | Windows returned `WinError 1314`; this process did not have the privilege required to create symlinks. |
| `tests/test_security_validation.py` POSIX permission test | POSIX mode bits are not portable to Windows. |
| `tests/test_session_index.py` POSIX permission test | POSIX mode bits are not portable to Windows. |

### Existing Linux VM run (prior revision; not rerun at this HEAD)

The existing [PPS-16 security validation report](./security-validation.md)
records user-run results from commit `c3c4492` on Python 3.12.3:

| Command | Recorded result |
|---|---|
| Two targeted POSIX permission tests | 2 passed |
| `python3.12 -m pytest -q tests/test_export_service.py` | 17 passed |
| `python3.12 -m pytest -q` | 133 passed |

These are evidence from `c3c4492`, not a rerun at `8f69bde`. The changes
between those commits are documentation-only, but final PPS-19 evidence still
requires a run against the integrated revision.

## Limitations and follow-up

- Run the native Python 3.12 test command on the Linux VM at the final
  integrated revision and record its actual skips and failures.
- The prior Linux run did not generate coverage; coverage must be measured
  separately on the VM if it is to be reported as Linux coverage.
- See [System-Validation Report](./system-validation-report.md) for live
  capture results and outstanding end-to-end checks.
