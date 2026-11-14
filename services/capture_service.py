import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.types import Result, Status
from services.session_index import SessionIndex, SessionRecord

IFF_UP = 0x1
DEFAULT_SESSION_ROOT = (
    Path.home() / ".local" / "share" / "pocket-packet-sniffer" / "sessions"
)
PROCESS_STOP_TIMEOUT = 5
MONITOR_INTERVAL_SECONDS = 1.0
MAX_CAPTURE_DURATION_SECONDS = 24 * 60 * 60
ALLOWED_PROTOCOL_FILTERS = frozenset({"tcp", "udp", "icmp"})

DEFAULT_ZEEK_POLICY = (
    Path(__file__).resolve().parents[1] / "zeek" / "pps05.zeek"
)

@dataclass(frozen=True)
class CaptureSession:
    session_id: str
    interface_name: str
    session_directory: Path
    pcap_path: Path
    zeek_directory: Path
    duration_seconds: int | None = None
    protocol_filter: str | None = None


@dataclass
class _RunningCapture:
    session: CaptureSession
    zeek_process: subprocess.Popen
    tcpdump_process: subprocess.Popen
    started_at: datetime
    started_monotonic: float
    duration_seconds: int | None
    protocol_filter: str | None
    ended_at: datetime | None = None
    monitor_stop: threading.Event = field(default_factory=threading.Event)
    monitor_thread: threading.Thread | None = None


def interface_is_up(interface_name: str) -> bool:
    flags_path = Path("/sys/class/net") / interface_name / "flags"
    flags = int(flags_path.read_text(encoding="ascii").strip(), 16)
    return bool(flags & IFF_UP)


def interface_has_carrier(interface_name: str) -> bool | None:
    """Return Linux link state when sysfs exposes it, otherwise ``None``.

    A missing or unsupported carrier attribute is deliberately *unknown*, not a
    disconnect.  On Linux, ``carrier == 0`` detects a cable/link loss that can
    leave the administrative IFF_UP flag set.  Other platforms retain the
    existing interface-removal and process-health monitoring.
    """
    carrier_path = Path("/sys/class/net") / interface_name / "carrier"
    try:
        value = carrier_path.read_text(encoding="ascii").strip()
    except (FileNotFoundError, OSError):
        return None
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def validate_duration(duration: int | str | None) -> Result[int | None]:
    """Validate a bounded duration before any capture command is launched."""
    if duration is None or duration == "":
        return Result(Status.OK, None)
    if isinstance(duration, bool):
        return Result(Status.INVALID_INPUT, detail="Duration must be a whole number of seconds.")
    if isinstance(duration, str):
        if not duration.isdecimal():
            return Result(Status.INVALID_INPUT, detail="Duration must be a whole number of seconds.")
        normalized_duration = duration.lstrip("0") or "0"
        if len(normalized_duration) > len(str(MAX_CAPTURE_DURATION_SECONDS)):
            return Result(
                Status.INVALID_INPUT,
                detail=(
                    "Duration must be between 1 and "
                    f"{MAX_CAPTURE_DURATION_SECONDS} seconds."
                ),
            )
        duration = int(normalized_duration)
    if not isinstance(duration, int) or not 0 < duration <= MAX_CAPTURE_DURATION_SECONDS:
        return Result(
            Status.INVALID_INPUT,
            detail=(
                "Duration must be between 1 and "
                f"{MAX_CAPTURE_DURATION_SECONDS} seconds."
            ),
        )
    return Result(Status.OK, duration)


def validate_protocol_filter(protocol_filter: str | None) -> Result[str | None]:
    """Only permit a small BPF allowlist; never accept arbitrary expressions."""
    if protocol_filter is None or protocol_filter == "":
        return Result(Status.OK, None)
    if not isinstance(protocol_filter, str):
        return Result(Status.INVALID_INPUT, detail="Protocol filter must be TCP, UDP, or ICMP.")
    normalized = protocol_filter.lower()
    if normalized not in ALLOWED_PROTOCOL_FILTERS:
        return Result(
            Status.INVALID_INPUT,
            detail="Protocol filter must be one of: tcp, udp, icmp.",
        )
    return Result(Status.OK, normalized)


def discover_interfaces() -> list[str]:
    return [name for _, name in socket.if_nameindex()]


class CaptureService:
    def __init__(
        self,
        interface_discoverer: Callable[[], list[str]] = discover_interfaces,
        interface_up_checker: Callable[[str], bool] = interface_is_up,
        interface_carrier_checker: Callable[[str], bool | None] = interface_has_carrier,
        session_root: Path = DEFAULT_SESSION_ROOT,
        executable_locator: Callable[[str], str | None] = shutil.which,
        process_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
        zeek_policy_path: Path = DEFAULT_ZEEK_POLICY,
        session_index: SessionIndex | None = None,
        event_notifier: Callable[[str], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        monitor_interval_seconds: float = MONITOR_INTERVAL_SECONDS,
    ) -> None:
        self._interface_discoverer = interface_discoverer
        self._interface_up_checker = interface_up_checker
        self._interface_carrier_checker = interface_carrier_checker
        self._session_root = Path(session_root)
        self._executable_locator = executable_locator
        self._process_factory = process_factory
        self._zeek_policy_path = Path(zeek_policy_path)
        self._session_index = session_index or SessionIndex(self._session_root)
        self._running_captures: dict[str, _RunningCapture] = {}
        self._interface_sessions: dict[str, str] = {}
        self._lock = threading.RLock()
        self._last_error = ""
        self._event_notifier = event_notifier
        self._clock = clock
        self._monitor_interval_seconds = monitor_interval_seconds

    @property
    def last_error(self) -> str:
        """Detail for the most recent stop failure, if any."""
        return self._last_error

    def set_event_notifier(self, event_notifier: Callable[[str], None] | None) -> None:
        """Set the dashboard callback used for asynchronous capture events."""
        self._event_notifier = event_notifier

    def list_completed_sessions(self) -> Result[list[SessionRecord]]:
        return self._session_index.list_sessions()

    def list_interfaces(self) -> Result[list[str]]:
        try:
            interfaces = self._interface_discoverer()
        except OSError as error:
            return Result(
                status=Status.INTERNAL_ERROR,
                detail=f"Could not discover network interfaces: {error}",
            )

        return Result(status=Status.OK, value=list(interfaces))

    def validate_interface(self, interface_name: str) -> Result[None]:
        if (
            not isinstance(interface_name, str)
            or not interface_name
            or interface_name != interface_name.strip()
        ):
            return Result(
                status=Status.INVALID_INPUT,
                detail="Interface name must be a non-empty name without surrounding whitespace.",
            )

        interfaces_result = self.list_interfaces()
        if interfaces_result.status is not Status.OK:
            return Result(
                status=interfaces_result.status,
                detail=interfaces_result.detail,
            )

        if interface_name not in interfaces_result.value:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Interface {interface_name!r} is not available.",
            )

        try:
            is_up = self._interface_up_checker(interface_name)
        except FileNotFoundError:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Interface {interface_name!r} is no longer available.",
            )
        except (OSError, ValueError) as error:
            return Result(
                status=Status.INTERNAL_ERROR,
                detail=f"Could not check the state of interface {interface_name!r}: {error}",
            )

        if not is_up:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Interface {interface_name!r} is not up.",
            )

        return Result(status=Status.OK)

    def start_capture(
        self,
        interface_name: str,
        duration: int | str | None = None,
        protocol_filter: str | None = None,
    ) -> Result[CaptureSession]:
        duration_result = validate_duration(duration)
        if duration_result.status is not Status.OK:
            return Result(duration_result.status, detail=duration_result.detail)
        filter_result = validate_protocol_filter(protocol_filter)
        if filter_result.status is not Status.OK:
            return Result(filter_result.status, detail=filter_result.detail)
        validation = self.validate_interface(interface_name)
        if validation.status is not Status.OK:
            return Result(status=validation.status, detail=validation.detail)

        with self._lock:
            if interface_name in self._interface_sessions:
                return Result(
                    status=Status.INVALID_INPUT,
                    detail=f"A capture is already running on interface {interface_name!r}.",
                )

            zeek_executable = self._executable_locator("zeek")
            if zeek_executable is None:
                return Result(
                    status=Status.ZEEK_ERROR,
                    detail="Zeek is not installed or is not available on PATH.",
                )

            tcpdump_executable = self._executable_locator("tcpdump")
            if tcpdump_executable is None:
                return Result(
                    status=Status.INTERNAL_ERROR,
                    detail="tcpdump is not installed or is not available on PATH.",
                )

            session_id = uuid.uuid4().hex
            session_directory = self._session_root / session_id
            zeek_directory = session_directory / "zeek"
            pcap_path = session_directory / "capture.pcap"
            session = CaptureSession(
                session_id=session_id,
                interface_name=interface_name,
                session_directory=session_directory,
                pcap_path=pcap_path,
                zeek_directory=zeek_directory,
                duration_seconds=duration_result.value,
                protocol_filter=filter_result.value,
            )

            zeek_process = None
            tcpdump_process = None
            try:
                self._ensure_private_directory(self._session_root)
                self._create_private_directory(session_directory)
                self._create_private_directory(zeek_directory)
                self._create_private_file(pcap_path).close()
                zeek_process = self._launch_zeek(
                    zeek_executable, session, filter_result.value
                )
                tcpdump_process = self._launch_tcpdump(
                    tcpdump_executable, session, filter_result.value
                )
            except PermissionError as error:
                failed_processes = [
                    process
                    for process in (zeek_process, tcpdump_process)
                    if process is not None
                ]
                cleanup_errors = self._stop_processes(failed_processes)
                detail = f"Permission denied while starting capture: {error}"
                if cleanup_errors:
                    detail += "; cleanup failed: " + "; ".join(cleanup_errors)
                return Result(status=Status.PERMISSION_ERROR, detail=detail)
            except OSError as error:
                failed_processes = [
                    process
                    for process in (zeek_process, tcpdump_process)
                    if process is not None
                ]
                cleanup_errors = self._stop_processes(failed_processes)
                detail = f"Could not start capture: {error}"
                if cleanup_errors:
                    detail += "; cleanup failed: " + "; ".join(cleanup_errors)
                return Result(status=Status.IO_ERROR, detail=detail)

            failed_process = self._failed_startup_process(
                zeek_process, tcpdump_process
            )
            if failed_process is not None:
                cleanup_errors = self._stop_processes(
                    [zeek_process, tcpdump_process]
                )
                detail = self._startup_error_detail(failed_process, session)
                if cleanup_errors:
                    detail += "; cleanup failed: " + "; ".join(cleanup_errors)
                status = (
                    Status.ZEEK_ERROR
                    if failed_process is zeek_process
                    else Status.IO_ERROR
                )
                return Result(status=status, detail=detail)

            self._running_captures[session_id] = _RunningCapture(
                session=session,
                zeek_process=zeek_process,
                tcpdump_process=tcpdump_process,
                started_at=datetime.now(timezone.utc),
                started_monotonic=self._clock(),
                duration_seconds=duration_result.value,
                protocol_filter=filter_result.value,
            )
            self._interface_sessions[interface_name] = session_id
            self._start_monitor(session_id)
            return Result(status=Status.OK, value=session)

    def stop_capture(self, session_id: str) -> Status:
        with self._lock:
            self._last_error = ""
            capture = self._running_captures.get(session_id)
            if capture is None:
                return Status.NOT_FOUND
            capture.monitor_stop.set()

            errors: list[str] = []
            if capture.ended_at is None:
                errors.extend(
                    self._stop_processes(
                        [capture.tcpdump_process, capture.zeek_process]
                    )
                )
                processes_stopped = all(
                    process.poll() is not None
                    for process in (
                        capture.tcpdump_process,
                        capture.zeek_process,
                    )
                )
                if processes_stopped:
                    capture.ended_at = datetime.now(timezone.utc)
                    self._interface_sessions.pop(
                        capture.session.interface_name, None
                    )

            permission_error = False
            if capture.ended_at is not None:
                self._interface_sessions.pop(capture.session.interface_name, None)
                try:
                    self._restrict_session_files(capture.session.session_directory)
                    record = self._completed_session_record(capture)
                    index_result = self._session_index.add_completed_session(record)
                    if index_result.status is not Status.OK:
                        errors.append(index_result.detail)
                        permission_error = (
                            index_result.status is Status.PERMISSION_ERROR
                        )
                    else:
                        self._running_captures.pop(session_id, None)
                except PermissionError as error:
                    permission_error = True
                    errors.append(
                        f"Permission denied while finalizing session files: {error}"
                    )
                except OSError as error:
                    errors.append(
                        f"Could not finalize session files or index: {error}"
                    )

            if errors:
                self._last_error = "; ".join(error for error in errors if error)
                return (
                    Status.PERMISSION_ERROR
                    if permission_error
                    else Status.IO_ERROR
                )
            return Status.OK

    def _start_monitor(self, session_id: str) -> None:
        """Start a daemon health monitor after a session is fully registered."""
        capture = self._running_captures[session_id]
        monitor = threading.Thread(
            target=self._monitor_capture,
            args=(session_id,),
            name=f"capture-monitor-{session_id[:8]}",
            daemon=True,
        )
        capture.monitor_thread = monitor
        monitor.start()

    def _monitor_capture(self, session_id: str) -> None:
        while True:
            with self._lock:
                capture = self._running_captures.get(session_id)
                if capture is None or capture.monitor_stop.is_set():
                    return
                stop_event = capture.monitor_stop
            if stop_event.wait(self._monitor_interval_seconds):
                return
            self._monitor_once(session_id)

    def _monitor_once(self, session_id: str) -> None:
        """Perform one deterministic, passive health check for a testable monitor."""
        with self._lock:
            capture = self._running_captures.get(session_id)
            if capture is None or capture.monitor_stop.is_set():
                return
            if (
                capture.duration_seconds is not None
                and self._clock() - capture.started_monotonic
                >= capture.duration_seconds
            ):
                event = "Capture duration expired; stopping capture safely."
            else:
                event = self._capture_health_problem(capture)
        if event is None:
            return
        # Notification precedes potentially slow process shutdown so a terminal
        # blocked in input receives the warning within one monitor interval.
        self._notify(event)
        status = self.stop_capture(session_id)
        if status is not Status.OK:
            self._notify(
                f"ERROR: capture finalization failed after automatic stop: {self.last_error}"
            )

    def _capture_health_problem(self, capture: _RunningCapture) -> str | None:
        try:
            interfaces = self._interface_discoverer()
        except OSError:
            interfaces = None
        if interfaces is not None and capture.session.interface_name not in interfaces:
            return f"Interface {capture.session.interface_name!r} was removed; stopping capture safely."

        try:
            carrier = self._interface_carrier_checker(capture.session.interface_name)
        except OSError:
            carrier = None
        if carrier is False:
            return f"Link loss on interface {capture.session.interface_name!r}; stopping capture safely."

        try:
            is_up = self._interface_up_checker(capture.session.interface_name)
        except FileNotFoundError:
            return f"Interface {capture.session.interface_name!r} was removed; stopping capture safely."
        except (OSError, ValueError):
            is_up = True  # unknown state must not be treated as a disconnect
        if not is_up:
            return f"Interface {capture.session.interface_name!r} is no longer up; stopping capture safely."

        for name, process in (
            ("tcpdump", capture.tcpdump_process),
            ("Zeek", capture.zeek_process),
        ):
            returncode = process.poll()
            if returncode is not None:
                return f"{name} exited unexpectedly (exit code {returncode}); stopping capture safely."
        return None

    def _notify(self, message: str) -> None:
        notifier = self._event_notifier
        if notifier is not None:
            try:
                notifier(message)
            except Exception:
                # A terminal callback must never crash or prevent capture cleanup.
                pass

    def _completed_session_record(
        self, capture: _RunningCapture
    ) -> SessionRecord:
        if capture.ended_at is None:
            raise RuntimeError("session must be stopped before it is indexed")
        log_paths = tuple(
            sorted(
                path.resolve()
                for path in capture.session.zeek_directory.rglob("*")
                if path.is_file()
            )
        )
        return SessionRecord(
            session_id=capture.session.session_id,
            interface_name=capture.session.interface_name,
            started_at=capture.started_at,
            ended_at=capture.ended_at,
            pcap_path=capture.session.pcap_path,
            zeek_directory=capture.session.zeek_directory,
            zeek_log_paths=log_paths,
        )

    def _create_private_directory(self, path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        path.chmod(0o700)

    def _ensure_private_directory(self, path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.is_dir():
            raise NotADirectoryError(f"{path} is not a directory")
        path.chmod(0o700)

    def _create_private_file(self, path: Path):
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        return os.fdopen(descriptor, "wb")

    def _launch_zeek(
        self, executable: str, session: CaptureSession, protocol_filter: str | None
    ) -> subprocess.Popen:
        stdout_path = session.session_directory / "zeek.stdout.log"
        stderr_path = session.session_directory / "zeek.stderr.log"
        with (
            self._create_private_file(stdout_path) as stdout_file,
            self._create_private_file(stderr_path) as stderr_file,
        ):
            arguments = [executable, "-i", session.interface_name]
            if protocol_filter is not None:
                arguments.extend(["-f", protocol_filter])
            arguments.extend(["-C", str(self._zeek_policy_path)])
            return self._process_factory(
                arguments,
                cwd=session.zeek_directory,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
            )

    def _launch_tcpdump(
        self, executable: str, session: CaptureSession, protocol_filter: str | None
    ) -> subprocess.Popen:
        stderr_path = session.session_directory / "tcpdump.stderr.log"
        with self._create_private_file(stderr_path) as stderr_file:
            arguments = [
                executable,
                "-U",
                "-n",
                "-i",
                session.interface_name,
                "-Z",
                "root",
                "-w",
                str(session.pcap_path),
            ]
            if protocol_filter is not None:
                arguments.append(protocol_filter)
            return self._process_factory(
                arguments,
                cwd=session.session_directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                shell=False,
            )

    def _failed_startup_process(
        self, zeek_process: subprocess.Popen, tcpdump_process: subprocess.Popen
    ) -> subprocess.Popen | None:
        if zeek_process.poll() is not None:
            return zeek_process
        if tcpdump_process.poll() is not None:
            return tcpdump_process
        return None

    def _startup_error_detail(
        self, process: subprocess.Popen, session: CaptureSession
    ) -> str:
        if process.args and Path(str(process.args[0])).name == "zeek":
            error_path = session.session_directory / "zeek.stderr.log"
            component = "Zeek"
        else:
            error_path = session.session_directory / "tcpdump.stderr.log"
            component = "tcpdump"
        try:
            output = error_path.read_text(encoding="utf-8").strip()
        except OSError:
            output = ""
        detail = f"{component} exited during startup."
        if output:
            detail += f" {output}"
        return detail

    def _stop_processes(self, processes: list[subprocess.Popen]) -> list[str]:
        errors: list[str] = []
        for process in processes:
            try:
                initial_returncode = process.poll()
                if initial_returncode is not None:
                    errors.append(
                        f"Process {process.args!r} exited before it was stopped "
                        f"(exit code {initial_returncode})."
                    )
                    continue
                try:
                    process.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    errors.append(
                        f"Could not interrupt process {process.args!r}: {error}"
                    )
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=PROCESS_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=PROCESS_STOP_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=PROCESS_STOP_TIMEOUT)
                        except subprocess.TimeoutExpired:
                            errors.append(
                                f"Process {process.args!r} did not exit after being killed."
                            )
            except OSError as error:
                errors.append(f"Could not stop process {process.args!r}: {error}")
                try:
                    process.kill()
                    process.wait(timeout=PROCESS_STOP_TIMEOUT)
                except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                    errors.append(
                        f"Could not kill process {process.args!r}: {cleanup_error}"
                    )
        return errors

    def _restrict_session_files(self, session_directory: Path) -> None:
        session_directory.chmod(0o700)
        for path in session_directory.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)
