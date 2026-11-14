import os
import signal
import socket
import stat
from pathlib import Path

import pytest

from core.types import Status
from services.capture_service import CaptureService


class FakeProcess:
    def __init__(self, arguments):
        self.args = arguments
        self.returncode = None

    def poll(self):
        return self.returncode

    def send_signal(self, received_signal):
        assert received_signal == signal.SIGINT
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9


class RecordingProcessFactory:
    def __init__(self):
        self.calls = []
        self.processes = []

    def __call__(self, arguments, **options):
        self.calls.append((arguments, options))
        process = FakeProcess(arguments)
        self.processes.append(process)
        return process


def make_service(tmp_path):
    process_factory = RecordingProcessFactory()
    service = CaptureService(
        interface_discoverer=lambda: ["eth0"],
        interface_up_checker=lambda _: True,
        session_root=tmp_path / "sessions",
        executable_locator=lambda name: f"/usr/bin/{name}",
        process_factory=process_factory,
        monitor_interval_seconds=3600,
    )
    return service, process_factory


@pytest.mark.parametrize(
    "interface_name",
    ["eth0; touch /tmp/pps16-marker", "../eth0", "eth0\n", " eth0"],
)
def test_unsafe_interfaces_are_rejected_before_subprocess_execution(
    tmp_path, interface_name
):
    service, process_factory = make_service(tmp_path)

    result = service.start_capture(interface_name)

    assert result.status is not Status.OK
    assert process_factory.calls == []


@pytest.mark.parametrize("duration", ["9" * 10000, "86401", "1.5", "-1"])
def test_unsafe_durations_are_rejected_before_subprocess_execution(
    tmp_path, duration
):
    service, process_factory = make_service(tmp_path)

    result = service.start_capture("eth0", duration=duration)

    assert result.status is Status.INVALID_INPUT
    assert process_factory.calls == []


@pytest.mark.parametrize(
    "protocol_filter",
    ["tcp and port 80", "tcp; touch /tmp/pps16-marker", "udp\n", "not a filter"],
)
def test_unsafe_filters_are_rejected_before_subprocess_execution(
    tmp_path, protocol_filter
):
    service, process_factory = make_service(tmp_path)

    result = service.start_capture("eth0", protocol_filter=protocol_filter)

    assert result.status is Status.INVALID_INPUT
    assert process_factory.calls == []


def test_capture_uses_passive_argument_lists_without_a_shell(tmp_path):
    service, process_factory = make_service(tmp_path)

    result = service.start_capture("eth0", duration="10", protocol_filter="tcp")

    assert result.status is Status.OK
    zeek_arguments, zeek_options = process_factory.calls[0]
    tcpdump_arguments, tcpdump_options = process_factory.calls[1]
    assert zeek_arguments == [
        "/usr/bin/zeek",
        "-i",
        "eth0",
        "-f",
        "tcp",
        "-C",
        str(service._zeek_policy_path),
    ]
    assert tcpdump_arguments == [
        "/usr/bin/tcpdump",
        "-U",
        "-n",
        "-i",
        "eth0",
        "-Z",
        "root",
        "-w",
        str(result.value.pcap_path),
        "tcp",
    ]
    assert zeek_options["shell"] is False
    assert tcpdump_options["shell"] is False
    assert service.stop_capture(result.value.session_id) is Status.OK


def test_capture_and_storage_path_do_not_open_outbound_sockets(
    tmp_path, monkeypatch
):
    def reject_network(*args, **kwargs):
        raise AssertionError("capture/storage attempted a socket network operation")

    for method in ("connect", "connect_ex", "send", "sendall", "sendto"):
        monkeypatch.setattr(socket.socket, method, reject_network)

    service, _ = make_service(tmp_path)
    result = service.start_capture("eth0")

    assert result.status is Status.OK
    assert service.stop_capture(result.value.session_id) is Status.OK


def test_path_like_unknown_session_ids_do_not_select_or_stop_sessions(
    tmp_path,
):
    service, process_factory = make_service(tmp_path)

    assert service.stop_capture("../outside") is Status.NOT_FOUND
    assert service.stop_capture(r"C:\outside\session") is Status.NOT_FOUND
    assert process_factory.calls == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable")
def test_session_zeek_output_and_index_are_owner_only_after_finalization(
    tmp_path,
):
    service, _ = make_service(tmp_path)
    result = service.start_capture("eth0")
    session = result.value
    nested_directory = session.zeek_directory / "nested"
    nested_directory.mkdir()
    zeek_log = nested_directory / "conn.log"
    zeek_log.write_text("synthetic test log\n", encoding="utf-8")
    zeek_log.chmod(0o644)

    assert service.stop_capture(session.session_id) is Status.OK

    assert stat.S_IMODE(service._session_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(session.session_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(session.zeek_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(session.pcap_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(zeek_log.stat().st_mode) == 0o600
    assert stat.S_IMODE(service._session_index.index_path.stat().st_mode) == 0o600

    for path in [service._session_root, *session.session_directory.rglob("*"),
                 service._session_index.index_path]:
        assert path.stat().st_uid == os.geteuid()
