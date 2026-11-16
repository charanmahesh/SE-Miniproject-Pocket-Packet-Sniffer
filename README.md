# Pocket Packet Sniffer

Pocket Packet Sniffer is a local terminal application for passively capturing
traffic on a selected interface, writing PCAP and Zeek logs, and summarizing
the resulting Zeek `conn.log`. It also supports alert toggling, browsing
completed sessions, and exporting PCAP/log files.

The current demonstration target is a **Linux VM**. Use only a network or
isolated test link that you own or are authorized to monitor.

## Features

- Select an available interface and start/stop capture.
- Set an optional maximum duration and an optional `tcp`, `udp`, or `icmp`
  filter.
- Write a local PCAP and Zeek logs.
- View protocol and connection summaries while capture is running.
- Toggle supported Zeek notice alerts.
- Browse completed sessions and export selected PCAP/log files.

Top talkers are ranked by **connection count**, not bytes or bandwidth. The
application is passive; this README's demo uses ordinary HTTP requests on a
local virtual link, not scans or injected traffic.

## Requirements

- Linux is required for the live-capture walkthrough below.
- Python 3.12 is recommended and matches the GitHub Actions workflow.
- Zeek, tcpdump, and libpcap must be installed and available to the capture
  process. The VM validation used Zeek 8.0.11 and tcpdump 4.99.4.
- The project Zeek policy loads `ncsa/bro-simple-scan`; install that package
  through Zeek's package manager if it is not already available:

  ```sh
  sudo /opt/zeek/bin/zkg install ncsa/bro-simple-scan
  ```

- Live packet capture needs appropriate OS permissions. The demo below runs
  the dashboard with `sudo`, so resulting files are owned by root. The
  application applies owner-only permissions to session artifacts.

The Python application uses the standard library. pytest is needed only for
tests; no dependency manifest is currently provided.

## Install and run tests

From the repository root:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install pytest
python -m pytest -q
```

The automated tests use synthetic Zeek logs and fake capture processes. They
do not perform live capture or PCAP replay.

## Isolated Linux VM demo

Use the existing `pps16-mon` / `pps16-peer` virtual link if you created it
during security validation. Do not connect this demo interface to a campus,
workplace, public, or otherwise unauthorized network.

### Prepare the virtual link

If the pair does not exist, create it once:

```sh
sudo ip netns add pps16-peer
sudo ip link add pps16-mon type veth peer name pps16-gen
sudo ip link set pps16-gen netns pps16-peer
sudo ip link set pps16-mon up
sudo ip -n pps16-peer link set lo up
sudo ip -n pps16-peer addr add 198.18.16.2/30 dev pps16-gen
sudo ip -n pps16-peer link set pps16-gen up
```

For the HTTP demo, the monitored side needs the peer address. Check first:

```sh
ip -4 addr show dev pps16-mon
```

Only if `198.18.16.1/30` is absent, assign it:

```sh
sudo ip addr add 198.18.16.1/30 dev pps16-mon
sudo ip link set pps16-mon up
sudo ip netns exec pps16-peer ping -c 2 -W 1 198.18.16.1
```

### Start a local HTTP server

In one VM terminal, bind the demo server only to the isolated link:

```sh
mkdir -p /tmp/pps-demo-www
printf 'Pocket Packet Sniffer VM demo\n' > /tmp/pps-demo-www/index.html
python3.12 -m http.server 8080 \
  --bind 198.18.16.1 \
  --directory /tmp/pps-demo-www
```

### Start the dashboard

From the repository root in another terminal, make Zeek available on `PATH`.
This launcher uses `/tmp/pps-demo-sessions` as the session root. The default
root-home path produced a tcpdump `Permission denied` in the current VM; this
temporary-root launcher is the suggested workaround and must be confirmed on
the VM before relying on it.

```sh
export PATH="/opt/zeek/bin:$PATH"
sudo env "PATH=$PATH" "$PWD/.venv/bin/python" - <<'PY'
from pathlib import Path

from dashboard import Dashboard
from services.capture_service import CaptureService

service = CaptureService(session_root=Path("/tmp/pps-demo-sessions"))
Dashboard(capture_service=service).run()
PY
```

### Generate traffic and demonstrate

In a third terminal, make a few HTTP requests from the isolated peer:

```sh
sudo ip netns exec pps16-peer python3.12 -c \
  'import urllib.request; [urllib.request.urlopen("http://198.18.16.1:8080/").read() for _ in range(5)]; print("HTTP requests complete")'
```

In the dashboard:

1. Choose **1** to list interfaces.
2. Choose **2**; enter `pps16-mon`, duration `120`, and filter `tcp`.
3. Generate the HTTP requests above. Choose **3** to view the summary; it
   should update as complete Zeek connection records arrive.
4. Choose **4** to stop and show the final summary.
5. Choose **8** to browse the completed session. To demonstrate export, first
   create an export directory with `sudo mkdir -p /tmp/pps-demo-export`,
   choose **9**, and select the desired export type.
6. Choose **7** to exit.

The dashboard also offers **5** to toggle alerts and **6** to view them. The
benign HTTP demo is not expected to create a scan alert.

## Storage and privacy

By default, the session index is at
`~/.local/share/pocket-packet-sniffer/sessions/index.json`; PCAP and Zeek files
are stored under the same session root. When run with `sudo`, `~` refers to
root's home. On Linux, session directories are restricted to mode `0700` and
regular files to `0600`. Do not make captured files world-readable to work
around permission errors.

If capture stops unexpectedly, inspect the session's `tcpdump.stderr.log` and
`zeek.stderr.log`. For the demo launcher above, these are beneath
`/tmp/pps-demo-sessions/<session-id>/`.

## Known limitations and reports

- The VM is the demo target; VM results do not establish Raspberry Pi
  performance. The current SRS still contains a Pi-specific NFR-02, which
  must be revised or formally waived to align the requirements with the VM
  target.
- The repository has no committed PCAP fixture or automated PCAP replay.
- The test and coverage reports are provisional and must be rerun on the final
  integrated revision and Linux VM.

See the [PPS-16 security validation report](docs/security-validation.md),
[PPS-17 Test Plan](documents/Pocket_Packet_Sniffer_Test_Plan.docx),
[PPS-19 unit-test report](docs/unit-test-report.md),
[PPS-19 system-validation report](docs/system-validation-report.md),
[PPS-19 code-coverage report](docs/code-coverage-report.md), and
[PPS-19 branch-coverage report](docs/branch-coverage-report.md).
