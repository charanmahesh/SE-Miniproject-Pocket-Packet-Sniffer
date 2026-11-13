import shutil
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.types import Result, Status, Summary
from dashboard import Dashboard
from services.capture_service import CaptureSession
from services.session_index import SessionRecord
from services.summary_service import SummaryService


@dataclass
class FakeSession:
    session_id: str = "s1"
    interface_name: str = "eth0"


class FakeCapture:
    def __init__(self):
        self.session = FakeSession()
        self.stopped = []

    def list_interfaces(self):
        return Result(Status.OK, ["eth0"])

    def list_completed_sessions(self):
        return Result(Status.OK, [])

    def start_capture(self, interface, duration=None, protocol_filter=None):
        return Result(Status.OK, self.session) if interface == "eth0" else Result(Status.INTERFACE_UNAVAILABLE, detail="not available")

    def stop_capture(self, session_id):
        self.stopped.append(session_id)
        return Status.OK

def make_past_session(session_id="past-1", interface="en0"):
    started = datetime(2026, 11, 10, 10, 0, tzinfo=UTC)

    return SessionRecord(
        session_id=session_id,
        interface_name=interface,
        started_at=started,
        ended_at=started + timedelta(minutes=5),
        pcap_path=Path(f"/tmp/{session_id}/capture.pcap"),
        zeek_directory=Path(f"/tmp/{session_id}/zeek"),
        zeek_log_paths=(),
    )

class NotifyingFakeCapture(FakeCapture):
    def set_event_notifier(self, notifier):
        self.notifier = notifier


class FakeSummary:
    def get_summary(self, session):
        return Result(Status.OK, Summary({"tcp": 1}, [("10.0.0.1", 1)], 1, None))

class FakeAlert:
    def __init__(self):
        self.enabled = {}
        self.alerts = []

    def is_enabled(self, session):
        return self.enabled.get(session.session_id, False)

    def set_enabled(self, session, enabled):
        self.enabled[session.session_id] = enabled
        return Result(Status.OK, enabled)

    def get_alerts(self, session):
        return Result(Status.OK, list(self.alerts))


def test_dashboard_guides_user_through_capture_summary_and_safe_stop():
    answers = iter(["1", "2", "eth0", "", "", "3", "4", "3", "7"])
    output = []
    capture = FakeCapture()
    Dashboard(capture, FakeSummary(), lambda _: next(answers), output.append).run()

    text = "\n".join(output)
    assert "Available interfaces: eth0" in text
    assert "Capture started" in text
    assert "Top talkers" in text
    assert "first host above is the top talker" in text
    assert text.count("Traffic summary") == 3  # live view, final view, post-stop view
    assert capture.stopped == ["s1"]


def test_dashboard_empty_and_invalid_choices_do_not_require_hardware():
    answers = iter(["", "3", "7"])
    output = []
    Dashboard(FakeCapture(), FakeSummary(), lambda _: next(answers), output.append).run()

    text = "\n".join(output)
    assert "choose an option" in text
    assert "No session is selected" in text

def test_dashboard_can_enable_and_disable_alerting():
    answers = iter(["2", "eth0", "", "", "5", "5", "7"])
    output = []
    capture = FakeCapture()
    alerts = FakeAlert()

    Dashboard(
        capture,
        FakeSummary(),
        lambda _: next(answers),
        output.append,
        alerts,
    ).run()

    text = "\n".join(output)

    assert "Alerting enabled for this session." in text
    assert "Alerting disabled for this session." in text
    assert alerts.enabled["s1"] is False
    assert capture.stopped == ["s1"]

def test_dashboard_displays_supported_alerts():
    answers = iter(["2", "eth0", "", "", "5", "6", "7"])
    output = []
    capture = FakeCapture()
    alerts = FakeAlert()

    alerts.alerts = [
        type(
            "FakeNotice",
            (),
            {
                "timestamp": "1234567890",
                "note": "Scan::Port_Scan",
                "source": "10.0.0.5",
                "destination": "10.0.0.1",
                "port": "445",
                "message": "TCP port scan detected",
                "priority": "HIGH",
                "reason": "TCP port scan detected",
            },
        )()
    ]

    Dashboard(
        capture,
        FakeSummary(),
        lambda _: next(answers),
        output.append,
        alerts,
    ).run()

    text = "\n".join(output)

    assert "Supported alerts (1)" in text
    assert "Scan::Port_Scan" in text
    assert "10.0.0.5" in text
    assert "10.0.0.1" in text
    assert "445" in text
    assert "TCP port scan detected" in text
    assert any("[HIGH] Scan::Port_Scan" in line for line in output)
    assert any("Reason: TCP port scan detected" in line for line in output)

def test_dashboard_displays_message_when_no_alerts_exist():
    answers = iter(["2", "eth0", "", "", "5", "6", "7"])
    output = []
    capture = FakeCapture()
    alerts = FakeAlert()

    Dashboard(
        capture,
        FakeSummary(),
        lambda _: next(answers),
        output.append,
        alerts,
    ).run()

    text = "\n".join(output)

    assert "No supported scan alerts detected for this session." in text
    assert capture.stopped == ["s1"]


def test_dashboard_displays_capture_storage_failure_detail():
    output = []
    capture = FakeCapture()
    capture.last_error = "Could not update session index: disk is full"
    capture.stop_capture = lambda _: Status.IO_ERROR
    dashboard = Dashboard(capture, FakeSummary(), output_fn=output.append)
    dashboard.session = capture.session
    dashboard.capture_active = True

    dashboard._stop_capture()

    assert any("disk is full" in line for line in output)


def test_dashboard_receives_disconnect_notice_while_waiting_for_input():
    waiting = threading.Event()
    release = threading.Event()
    output = []
    capture = NotifyingFakeCapture()

    def blocking_input(_):
        waiting.set()
        release.wait(timeout=2)
        return "7"

    dashboard = Dashboard(capture, FakeSummary(), blocking_input, output.append)
    runner = threading.Thread(target=dashboard.run)
    runner.start()
    assert waiting.wait(timeout=1)

    capture.notifier("Link loss on interface 'eth0'; stopping capture safely.")

    assert any("Link loss" in line for line in output)
    release.set()
    runner.join(timeout=2)
    assert not runner.is_alive()


def test_dashboard_renders_summary_from_synthetic_conn_log(
    tmp_path, sample_zeek_logs
):
    session_directory = tmp_path / "dashboard-fixture"
    zeek_directory = session_directory / "zeek"
    zeek_directory.mkdir(parents=True)
    shutil.copyfile(sample_zeek_logs / "conn.log", zeek_directory / "conn.log")
    session = CaptureSession(
        "dashboard-fixture",
        "eth0",
        session_directory,
        session_directory / "capture.pcap",
        zeek_directory,
    )
    output = []
    dashboard = Dashboard(
        FakeCapture(),
        SummaryService(),
        output_fn=output.append,
    )
    dashboard.session = session

    dashboard._view_summary()

    rendered = "\n".join(output)
    assert "Total connections: 3" in rendered
    assert "tcp: 2" in rendered
    assert "udp: 1" in rendered
    assert "192.0.2.10: 3 connection(s)" in rendered


def test_browse_past_sessions_displays_history():
    output = []
    capture = FakeCapture()
    capture.list_completed_sessions = lambda: Result(
        Status.OK,
        [make_past_session()]
    )

    dashboard = Dashboard(
        capture, FakeSummary(), input_fn=lambda _: "0",
        output_fn=output.append
    )

    dashboard._browse_past_sessions()

    text = "\n".join(output)
    assert "Past Capture Sessions" in text
    assert "past-1" in text
    assert "en0" in text
    assert "00:05:00" in text


def test_browse_past_sessions_handles_empty_history():
    output = []
    dashboard = Dashboard(
        FakeCapture(), FakeSummary(), output_fn=output.append
    )

    dashboard._browse_past_sessions()

    assert "No past capture sessions found." in "\n".join(output)


def test_browse_past_sessions_selects_session():
    output = []
    capture = FakeCapture()
    capture.list_completed_sessions = lambda: Result(
        Status.OK,
        [make_past_session()]
    )

    dashboard = Dashboard(
        capture, FakeSummary(), input_fn=lambda _: "1",
        output_fn=output.append
    )

    dashboard._browse_past_sessions()

    assert dashboard.session.session_id == "past-1"
    assert dashboard.session.interface_name == "en0"
    assert any("Selected past session" in line for line in output)


def test_browse_past_sessions_rejects_invalid_selection():
    output = []
    capture = FakeCapture()
    capture.list_completed_sessions = lambda: Result(
        Status.OK,
        [make_past_session()]
    )

    dashboard = Dashboard(
        capture, FakeSummary(), input_fn=lambda _: "99",
        output_fn=output.append
    )

    dashboard._browse_past_sessions()

    assert dashboard.session is None
    assert any("Invalid session selection" in line for line in output)

def test_historical_session_cannot_be_stopped():
    output = []
    capture = FakeCapture()
    dashboard = Dashboard(
        capture,
        FakeSummary(),
        output_fn=output.append,
    )

    dashboard.session = make_past_session()
    dashboard.capture_active = False

    dashboard._stop_capture()

    assert capture.stopped == []
    assert any(
        "Historical sessions cannot be stopped" in line
        for line in output
    )