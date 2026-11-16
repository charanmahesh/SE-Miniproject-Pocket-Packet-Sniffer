# System-Validation Report

**Status: PROVISIONAL — evidence spans more than one revision and is not the final integrated release report**

## Revision and environment

- Report date: 2026-11-16
- Current documentation/test branch: `pps17-test-plan-traceability`
- Current tested HEAD for Windows automated tests: `8f69bde2989c8b232f4d766ff46f53ddf9f7e9a0`
- `origin/main` at inspection: `198032cc1c8b91c7b7197ffee8fc5f89df0a0a33`
- The current branch is two commits ahead of `origin/main`; it is not integrated.
- Windows test host: Windows 10, Python 3.10.6.
- Prior Linux VM evidence: Python 3.12.3, pytest 9.2.0, Zeek 8.0.11,
  `ncsa/bro-simple-scan` 4.1, tcpdump 4.99.4, libpcap 1.10.4.
- Linux distribution/version was not recorded in the existing evidence.

The final demo target is a Linux VM, not a Raspberry Pi. No VM result is
presented as Raspberry Pi evidence.

No live system-validation run was performed on the Windows host for PPS-19.
The system results below are prior Linux VM evidence or the user's later
VM-reported dashboard attempt; they are separated by revision and outcome.

## System and integration evidence

| Check | Evidence and result | Status |
|---|---|---|
| Linux automated suite | User-provided run documented in [PPS-16 security validation](./security-validation.md): 133 passed at `c3c4492`. | PASS for that revision; not rerun at `8f69bde`. |
| Linux export and POSIX permissions | At `c3c4492`, the export suite reported 17 passed and the two targeted POSIX permission tests reported 2 passed. | PASS for that revision; not rerun at `8f69bde`. |
| Isolated veth capture | PPS-16 evidence reports a capture session started/stopped with status `OK`; the PCAP contained a peer ARP request. An outbound observer recorded 0 packets and 0 kernel drops. | PASS for the bounded VM check. It does not validate a physical NIC or dashboard-generated TCP summary. |
| Security process/egress observation (SEC-01, SEC-04) | The recorded process trace had no `connect()` calls; reviewed `sendto`/`sendmsg` calls targeted local `AF_NETLINK`. The isolated-link outbound observer recorded no packets. | PASS for the documented VM observation only. |
| Session permissions (SEC-02) | Recorded VM `stat` results were mode 700 for directories and 600 for files/index, owned by root because capture ran under `sudo`; `nobody` could not read the index or PCAP. | PASS for the recorded VM artifacts. |
| Input validation (SEC-03) | Automated validation and passive-argument tests passed in the documented Linux test suite. | PASS automated evidence; no live UI fuzzing was performed. |
| Export confinement (SEC-05) | Linux `tests/test_export_service.py` reported 17 passed with no skips in the recorded run. | PASS for that revision. |
| Latest dashboard capture attempt | User-provided VM output showed the dashboard start capture on `pps16-mon`, then tcpdump exited with code 1. Its stderr reported `Permission denied` opening `/root/.local/share/pocket-packet-sniffer/sessions/3106ad44eed148eca6c3d6e41ebf8f4b/capture.pcap`; capture finalization then failed. The interface was up, and a separate tcpdump listener without a PCAP output file could listen on it. | FAIL for this attempt; no dashboard PCAP or end-to-end summary is claimed. The exact VM checkout commit was not recorded. |

The suggested `/tmp/pps-demo-sessions` session-root workaround has not yet
been verified. The permission error is specific to opening the PCAP in the
default root-home session path; the underlying host policy/path cause has not
been established.

## Not run or still pending

- End-to-end dashboard capture to a writable session root, including a
  verified `conn.log`, live summary update, stop, session browse, and export.
- Supported Zeek scan-notice detection with an authorized end-to-end test
  input; synthetic notice parsing is not equivalent to live detection.
- Prerecorded-PCAP replay (NFR-04); the repository has no committed PCAP
  fixture/replay workflow.
- Timed novice usability task (NFR-05).
- Measured five-second disconnect response and readable partial PCAP on the
  VM (NFR-03); mocked checks are not a live timing result.
- Restart/reboot persistence (REQ-4.4).
- Opening an exported PCAP with Wireshark or tshark (REQ-4.5).
- Raspberry Pi-specific throughput/packet-loss testing is not part of the
  chosen VM demo target. The current SRS still contains a Pi-specific NFR-02;
  formally revise or waive it before treating the requirement baseline as
  aligned with the VM target.

## Linux VM rerun required for final PPS-19

These reports were prepared on Windows. After the branch is integrated, first
verify that the VM checkout is clean before changing revisions; preserve any
local work. Then run the appropriate Python 3.12 suite at the integrated
revision:

```sh
git status --short
git fetch origin
git switch <integrated-branch>
git rev-parse HEAD
python3.12 --version
/tmp/pps16-venv/bin/python -m pytest -q -rs
```

Rerun the isolated dashboard demo and record the actual session path, tcpdump
stderr, PCAP read result, Zeek log contents, summary update, and export result.
Use only the authorized isolated veth pair. Do not generate scans or capture
unrelated network traffic for this report.

For the detailed prior security evidence and VM commands, see
[PPS-16 security validation](./security-validation.md).
