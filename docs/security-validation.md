# PPS-16 Security Validation

## Status

PPS-16 is **partially validated and still open**. Automated checks for input
validation, export path safety, and the mocked capture path passed. Live
network checks were not run because this validation environment is Windows,
not the project's selected Linux VM. POSIX permission and symlink checks were
skipped where Windows could not provide those semantics; run them on the Linux
VM before closing the issue.

Do not treat the passing mocked checks as proof of live network behavior or
export safety.

## Requirements and traceability

The SRS Section 6.3 states that captured data is stored locally by default,
with no automatic transmission, and expects OS-level access controls. Its
Section 6.2 also requires passive capture. The numbered SEC-01 through SEC-05
wording below is in Section 6.3 of the combined SRS/SAD/STP PDF and in the
Test Plan; the SRS's own Section 6.3 does not number those five requirements.

| Requirement | Validation and evidence | Result |
|---|---|---|
| SEC-01 - Captured data is local; no outbound network connection carries captured data. | Source review found no application HTTP, URL, or outbound socket APIs; `socket.if_nameindex()` is used for interface enumeration. `test_capture_and_storage_path_do_not_open_outbound_sockets` guards Python socket connect/send calls during a mocked capture and finalization. | Automated/mock check passed. A Linux VM process-family and network observation remains required; Zeek/tcpdump behavior is not proven by a fake-process test. |
| SEC-02 - Session directories/files and index are readable only by the owning OS user (700/600 or stricter). | Capture finalization sets directories to 700 and regular files to 600. `test_session_zeek_output_and_index_are_owner_only_after_finalization`, `test_start_capture_launches_live_zeek_and_packet_buffered_pcap`, and `test_index_and_storage_directory_are_owner_only_on_posix` cover modes. | POSIX permission assertions were skipped on this Windows host. Verify modes and access by a second OS user in the Linux VM. |
| SEC-03 - Interface, capture filter, and duration are validated before use and not passed unsanitized to a shell or Zeek. | Parameterized malicious-input tests verify rejection before process creation. Process argument lists and `shell=False` are checked by `test_capture_uses_passive_argument_lists_without_a_shell`. | Automated tests passed. A long decimal duration exposed potentially unbounded integer conversion; it is now length-checked before conversion, with a regression test. |
| SEC-04 - Capture is passive and sends no probes or injected packets on the monitored segment. | `test_capture_uses_passive_argument_lists_without_a_shell` checks the mocked Zeek/tcpdump command lines are interface listeners and not probe/injection commands. Source review found no packet-generation API. | Code-level/mock check passed. An isolated Linux VM observation remains required. |
| SEC-05 - Exports go only to the selected destination and session names cannot traverse paths. | PPS-15's `ExportService` validates session IDs, confines Zeek log paths to the recorded Zeek directory, rejects symlink sources/destinations, and creates outputs exclusively with mode 600. `tests/test_export_service.py` exercises these cases. | Core automated tests passed. Non-string session IDs and blank destinations exposed exceptions/unsafe current-directory export; both were fixed. Three symlink tests and the POSIX output-mode test were skipped on Windows and remain to be run on Linux. |

## Test environment and tested revision

- Validation date: 2026-11-14.
- Branch: `pps16-security-validation`.
- Tested HEAD before these uncommitted PPS-16 changes:
  `198032cc1c8b91c7b7197ffee8fc5f89df0a0a33`
  (`[PPS-15] Export sessions safely (#32)`).
- PPS-15 is present locally as a fast-forward from `origin/main`; both PPS-15
  and the uncommitted PPS-16 changes are preserved.
- Host: Windows; Python 3.10.6; pytest 9.1.1.
- No Linux VM, live interface, Zeek process, tcpdump process, or real network
  traffic was available for this run. Capture subprocesses in automated tests
  are fakes.
- The GitHub Actions workflow uses Python 3.12. The local Python 3.10 runtime
  cannot collect `tests/test_dashboard.py`, which imports `datetime.UTC`
  (available starting in Python 3.11). A one-process compatibility shim was
  used to run the suite locally; it aliases `datetime.UTC` to
  `datetime.timezone.utc` and does not change repository files.
- Project target deviation: use a Linux VM instead of the originally specified
  Raspberry Pi. VM tests can validate Linux permissions and virtual-interface
  behavior, but cannot establish Raspberry Pi NIC/driver behavior, Wi-Fi
  monitor-mode support, GPIO/peripheral behavior, power use, or Raspberry
  Pi-specific throughput and packet-loss claims. Record VM results as VM
  results only; revise the SRS/STP performance target if the Pi is no longer a
  target.

## Automated test results

Expected results are rejection before process execution for unsafe inputs,
owner-only POSIX modes after finalization, and only the documented passive
listener argument lists. Actual results from this Windows host:

| Test(s) | Expected | Actual |
|---|---|---|
| `test_capture_and_storage_path_do_not_open_outbound_sockets` | Mocked application capture/storage does not connect or send on Python sockets. | Passed. This does not observe subprocess internals or prove live network silence. |
| `test_session_zeek_output_and_index_are_owner_only_after_finalization` | POSIX directories are 700, regular files/index are 600, and artifacts belong to the effective user. | Skipped: POSIX mode/ownership checks are not portable to Windows. |
| `test_unsafe_interfaces_are_rejected_before_subprocess_execution` | Malicious interface strings do not launch a subprocess. | Passed (4 parameter cases). |
| `test_unsafe_durations_are_rejected_before_subprocess_execution` | Malformed, out-of-range, and very long durations return `INVALID_INPUT` without launching a subprocess. | Passed (4 parameter cases). |
| `test_unsafe_filters_are_rejected_before_subprocess_execution` | Non-allowlisted filters return `INVALID_INPUT` without launching a subprocess. | Passed (4 parameter cases). |
| `test_capture_uses_passive_argument_lists_without_a_shell` | Zeek/tcpdump receive the expected list arguments with `shell=False`; capture starts/stops. | Passed with fake subprocesses. No packets were observed. |
| `test_path_like_unknown_session_ids_do_not_select_or_stop_sessions` | Unknown path-like IDs cannot stop a capture. | Passed. It does not cover export path handling. |
| `test_export_writes_selected_files_with_safe_names_and_contents` | Selected PCAP/log bytes are copied under generated names in the selected directory. | Passed. |
| `test_exported_files_are_owner_only_on_posix` | Exported regular files are mode 600 and owned by the effective user. | Skipped on Windows; run on Linux. |
| `test_invalid_session_ids_are_rejected_without_writing_files` | Traversal, absolute, dotted, blank, and non-string IDs return `INVALID_INPUT` without output. | Passed (6 parameter cases); non-string IDs now return a result instead of raising `TypeError`. |
| `test_invalid_destinations_are_rejected_instead_of_defaulting_to_cwd` | Blank or non-path destinations are rejected rather than resolving to the current directory. | Passed (3 parameter cases); empty strings previously exported into the working directory and are now rejected. |
| `test_missing_or_non_directory_destinations_are_rejected` | A missing path or file destination cannot receive exports. | Passed. |
| `test_symlink_destination_is_rejected_without_writing_through_it`, `test_symlinked_source_is_rejected_without_copying_its_target`, `test_symlink_at_export_filename_is_not_followed_or_overwritten` | Symlink destinations, sources, and output names are rejected without writing through them. | Skipped on this Windows host because symlink creation was unavailable. Run on Linux. |
| `test_zeek_log_outside_session_directory_is_rejected` | A Zeek path outside the selected session is rejected. | Passed. |
| `test_existing_export_is_not_overwritten` | An existing export remains unchanged and is not overwritten. | Passed. |
| Existing `test_invalid_durations_are_rejected_before_commands_launch`, `test_unsafe_protocol_filters_are_rejected_before_commands_launch`, interface validation tests, capture command tests, and POSIX index-permission test | Preserve existing rejection, command construction, and storage behavior. | Passed where runnable; the POSIX index-permission test is skipped on Windows. |

Commands and actual results:

```text
python -m pytest -q tests/test_security_validation.py
15 passed, 1 skipped

python -m pytest -q tests/test_export_service.py
13 passed, 4 skipped

python -m pytest -q tests/test_export_service.py tests/test_security_validation.py
28 passed, 5 skipped

python -m pytest -q tests/test_export_service.py tests/test_security_validation.py tests/test_capture_options_monitoring.py tests/test_capture_service.py tests/test_capture_lifecycle.py tests/test_session_index.py
86 passed, 6 skipped

python -m pytest -q
FAILED during collection: tests/test_dashboard.py cannot import datetime.UTC
from the installed Python 3.10.6 runtime. No tests ran in this invocation.

python -c "import datetime; datetime.UTC = datetime.timezone.utc; import pytest; raise SystemExit(pytest.main(['-q']))"
127 passed, 6 skipped

git diff --check
Passed (no whitespace errors).
```

The shimmed run is useful regression evidence, but it does not replace a
native full-suite run on the workflow's Python 3.12 or on the Linux VM.

## Linux VM setup and live verification

Use only a VM and virtual network that you administer. Do not bridge the test
interface to a campus, workplace, public, or otherwise unauthorized network.
The following steps create an isolated veth pair on one Linux VM; the monitored
side has no IP address, so generated test traffic does not receive an
application-host IP response.

1. Install the project runtime and inspection tools. Use Python 3.12 to match
   CI (or another version supported by the project), and install Zeek using
   the official package instructions for the VM distribution. Confirm the
   required Zeek scan package used by `zeek/pps05.zeek` is installed before
   starting capture.

   ```sh
   python3.12 --version
   python3.12 -m venv /tmp/pps16-venv
   /tmp/pps16-venv/bin/python -m pip install pytest
   sudo apt install tcpdump iproute2 iputils-ping strace
   zeek --version
   tcpdump --version
   ```

   If the VM is not Debian/Ubuntu, use its package manager instead of `apt`.
   Do not run pytest with `sudo`.

2. Run the POSIX automated permission checks as the ordinary VM login user:

   ```sh
   /tmp/pps16-venv/bin/python -m pytest -q \
     tests/test_security_validation.py::test_session_zeek_output_and_index_are_owner_only_after_finalization \
     tests/test_session_index.py::test_index_and_storage_directory_are_owner_only_on_posix
   /tmp/pps16-venv/bin/python -m pytest -q tests/test_export_service.py
   ```

   Expected: both permission tests pass with directory mode 700, file/index
   mode 600, and ownership by the test process's effective UID. The export
   test module should run its symlink and mode checks without Windows skips.

3. Create a temporary isolated virtual link. The monitored interface
   (`pps16-mon`) intentionally has no IP address:

   ```sh
   sudo ip netns add pps16-peer
   sudo ip link add pps16-mon type veth peer name pps16-gen
   sudo ip link set pps16-gen netns pps16-peer
   sudo ip link set pps16-mon up
   sudo ip -n pps16-peer link set lo up
   sudo ip -n pps16-peer addr add 198.18.16.2/30 dev pps16-gen
   sudo ip -n pps16-peer link set pps16-gen up
   ip -br addr show pps16-mon
   sudo ip netns exec pps16-peer ip -br addr show pps16-gen
   ```

   Confirm `pps16-mon` has no assigned address and neither interface has a
   route to an external network.

4. In terminal A, observe packets leaving the monitored side. Keep this
   observer off the repository and save no capture file:

   ```sh
   sudo timeout 30 tcpdump -Q out -nn -i pps16-mon
   ```

   In terminal B, start the application and trace its process family's network
   syscalls. This uses `sudo`, so the session files will be owned by root; the
   application applies owner-only modes to them:

   ```sh
   sudo strace -ff -e trace=network -o /tmp/pps16-net.trace \
     python3.12 - <<'PY'
   import time
   from pathlib import Path

   from core.types import Status
   from services.capture_service import CaptureService

   service = CaptureService(session_root=Path("/tmp/pps16-sessions"))
   result = service.start_capture("pps16-mon")
   if result.status is not Status.OK:
       raise RuntimeError(result.detail)
   session = result.value
   print(session.session_id, session.session_directory)
   time.sleep(20)
   print(service.stop_capture(session.session_id).name)
   PY
   ```

   Run this from the repository root so Python can import the project. Start
   terminal A first, then B, then C before the 20-second capture ends. If
   `start_capture` reports an error, stop and resolve the dependency or
   permission problem; do not treat it as a pass. Check that the generated
   session contains a PCAP before interpreting capture results.

5. While the capture is active, in terminal C send a small, bounded test from
   the isolated peer:

   ```sh
   sudo ip netns exec pps16-peer ping -I pps16-gen -c 3 -W 1 198.18.16.1
   ```

   The ping is expected not to receive replies because `pps16-mon` has no IP
   address. Its ARP requests should be visible as inbound test traffic. The
   terminal-A egress observer should show no packets emitted from
   `pps16-mon`. Record that limitation: this validates reception of local
   virtual-link traffic, not a physical NIC.

6. Review only the trace files for the application and its children. The
   application tree should show capture-socket setup/reads, but no unexpected
   external `connect`, `sendto`, or `sendmsg` traffic. Correlate each PID with
   the traced `execve` output or process tree; do not attribute unrelated VM
   background traffic to the application. Review every unexpected socket
   operation rather than treating a raw `grep` result as a verdict:

   ```sh
   grep -HnE 'connect\(|sendto\(|sendmsg\(|sendmmsg\(' /tmp/pps16-net.trace.*
   ```

   For an additional observed-inbound check, run
   `sudo tcpdump -Q in -nn -i pps16-mon` in a separate terminal during the
   peer test. This observer is independent of the application's own
   subprocesses. Save the command, versions, interface names, and a concise
   conclusion, not sensitive traffic contents or captures in Git.

7. Check ownership/modes for the printed session path and index:

   Replace `<session-id>` below with the ID printed by the capture script; do
   not type the angle brackets.

   ```sh
   sudo stat -c '%a %U:%G %n' /tmp/pps16-sessions \
     /tmp/pps16-sessions/index.json \
     /tmp/pps16-sessions/<session-id> \
     /tmp/pps16-sessions/<session-id>/capture.pcap
   ```

   Expect directories to be `700` and regular files to be `600`. Because the
   capture was run with `sudo`, the owner should be `root`; owner-only means
   root-only for those artifacts. Check that a second account cannot read
   representative files:

   ```sh
   sudo -u nobody test ! -r /tmp/pps16-sessions/index.json
   sudo -u nobody test ! -r /tmp/pps16-sessions/<session-id>/capture.pcap
   ```

   Both commands should exit successfully. These checks show OS permission
   behavior for the effective owner, not application-level authentication.
   Do not make artifacts world-readable to transfer them; use a deliberate,
   separately secured copy if evidence must be shared.

8. Remove only the test resources after recording results:

   ```sh
   sudo ip netns del pps16-peer
   ```

   Remove only the specific trace files listed by
   `ls -1 /tmp/pps16-net.trace.*`. Remove `/tmp/pps16-sessions` only after
   confirming the path is exactly the temporary test directory and the
   synthetic test data is no longer needed.

### Root/sudo ownership note

When the Python process is started with `sudo`, `Path.home()` and the
effective UID generally refer to root. The default session root may therefore
be under `/root`, and root owns the files. The `tcpdump -Z root` option also
requests root as its post-open user. Mode 600/700 still restricts access to
that owner, but it does not make the regular login user the owner. Record the
effective UID, owner, and chosen `session_root`; do not claim the login user
owns root-run captures. The automated test validates the effective UID on
POSIX. Avoid changing permissions to make root-created captures readable by
all users.

## SEC-05 results and remaining follow-up

PPS-15 added `services/export_service.py`. The new tests cover:

- invalid, traversal, absolute, dotted, empty, and non-string session IDs;
- empty, missing, non-directory, and symlinked destinations;
- symlinked input files and symlinked output filenames;
- Zeek logs outside the recorded session directory;
- existing export files, which must remain unchanged; and
- exported-file mode 600 and effective-user ownership on POSIX.

The initial tests exposed two defects. Passing `None` or an integer as
`session_id` raised `TypeError` before the service could return an error; the
service now returns `INVALID_INPUT`. Passing an empty destination resolved to
the current working directory and wrote the synthetic test files there; the
service now rejects empty and whitespace-only destinations. Those two
synthetic files were verified and removed after the repro.

The tests for symlink behavior and POSIX exported-file permissions are present
but were skipped on Windows. Run `tests/test_export_service.py` on the Linux
VM; do not mark those checks complete from the Windows run. Along with the
pending SEC-01/SEC-04 live observations and SEC-02 Linux ownership checks,
those skipped platform checks mean PPS-16 acceptance is not yet fully met.
