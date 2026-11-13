"""Small terminal controller for capture and PPS-04 traffic summaries."""

import threading
from collections.abc import Callable
from typing import Protocol

from core.types import Result, Status
from services.alert_service import AlertService
from services.capture_service import CaptureService, CaptureSession
from services.export_service import ExportService
from services.session_index import SessionRecord
from services.summary_service import SummaryService, render_summary

SUMMARY_REFRESH_INTERVAL_SECONDS = 1.0


class CaptureController(Protocol):
    def list_interfaces(self) -> Result[list[str]]: ...

    def start_capture(
        self,
        interface_name: str,
        duration: int | str | None = None,
        protocol_filter: str | None = None,
    ) -> Result[CaptureSession]: ...

    def stop_capture(self, session_id: str) -> Status: ...


class Dashboard:
    def __init__(
        self,
        capture_service: CaptureController | None = None,
        summary_service: SummaryService | None = None,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], None] = print,
        alert_service: AlertService | None = None,
        export_service: ExportService | None = None,
        summary_refresh_interval_seconds: float = SUMMARY_REFRESH_INTERVAL_SECONDS,
    ) -> None:
        if summary_refresh_interval_seconds <= 0:
            raise ValueError("Summary refresh interval must be greater than zero.")
        self.capture_service = capture_service or CaptureService()
        self.summary_service = summary_service or SummaryService()
        self.alert_service = alert_service or AlertService()
        self.export_service = export_service or ExportService()
        self.selected_record: SessionRecord | None = None
        self.input = input_fn
        self._output_fn = output_fn
        self._output_lock = threading.Lock()
        self._summary_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._summary_refresh_interval_seconds = summary_refresh_interval_seconds
        self._summary_refresh_stop: threading.Event | None = None
        self._summary_refresh_thread: threading.Thread | None = None
        self.output = self._write_output
        self.session = None
        self.capture_active = False
        set_notifier = getattr(self.capture_service, "set_event_notifier", None)
        if callable(set_notifier):
            set_notifier(self._on_capture_event)

    def run(self) -> None:
        self.output("Pocket Packet Sniffer - traffic dashboard")
        self.output("Choose an interface, start capture, view the summary, then stop safely.")
        try:
            while True:
                self.output(
                    "\n1) List interfaces  "
                    "2) Start capture  "
                    "3) View summary  "
                    "4) Stop capture  "
                    "5) Toggle alerting  "
                    "6) View alerts  "
                    "7) Exit  "
                    "8) Browse past sessions  "
                    "9) Export selected session   "
                )
                choice = self.input("Select an option: ").strip()
                if choice == "1":
                    self._list_interfaces()
                elif choice == "2":
                    self._start_capture()
                elif choice == "3":
                    self._view_summary()
                elif choice == "4":
                    self._stop_capture()
                elif choice == "5":
                    self._toggle_alerting()
                elif choice == "6":
                    self._view_alerts()
                elif choice == "7":
                    with self._state_lock:
                        capture_active = self.capture_active
                    if capture_active:
                        self.output("Stopping the active capture before exit...")
                        self._stop_capture()
                    break
                elif choice == "8":
                    self._browse_past_sessions()
                elif choice == "9":
                    self._export_session()
                else:
                    self.output("ERROR: input: choose an option from 1 to 9.")

        finally:
            self._stop_summary_refresh()
            set_notifier = getattr(self.capture_service, "set_event_notifier", None)
            if callable(set_notifier):
                set_notifier(None)

    def _write_output(self, message: str) -> None:
        with self._output_lock:
            self._output_fn(message)


    def _browse_past_sessions(self) -> None:
        """Browse and select a previously completed capture session."""
        with self._state_lock:
            if self.capture_active:
                self.output(
                    "ERROR: Stop the active capture before selecting a past session."
                )
                return

        list_sessions = getattr(
            self.capture_service, "list_completed_sessions", None
        )

        if not callable(list_sessions):
            self.output("ERROR: Session history is not supported by this capture service.")
            return

        result = list_sessions()

        if result.status is not Status.OK:
            self.output(f"ERROR: session history: {result.detail}")
            return

        sessions = result.value or []

        if not sessions:
            self.output("No past capture sessions found.")
            return

        self.output("\nPast Capture Sessions")
        self.output("=====================")

        for index, record in enumerate(sessions, start=1):
            duration = record.ended_at - record.started_at
            total_seconds = int(duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            self.output(
                f"{index}) Session: {record.session_id}\n"
                f"   Date: {record.started_at.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
                f"   Duration: {hours:02}:{minutes:02}:{seconds:02}\n"
                f"   Interface: {record.interface_name}"
            )

        self.output("0) Cancel")

        choice = self.input("Select a session number: ").strip()

        if choice == "0":
            self.output("Session selection cancelled.")
            return

        try:
            selected_index = int(choice)
        except ValueError:
            self.output("ERROR: Enter a valid session number.")
            return

        if selected_index < 1 or selected_index > len(sessions):
            self.output("ERROR: Invalid session selection.")
            return

        record = sessions[selected_index - 1]
        self.selected_record = record

        selected_session = CaptureSession(
            session_id=record.session_id,
            interface_name=record.interface_name,
            session_directory=record.pcap_path.parent,
            pcap_path=record.pcap_path,
            zeek_directory=record.zeek_directory,
        )

        with self._state_lock:
            if self.capture_active:
                self.output(
                    "ERROR: An active capture started during session selection."
                )
                return
            self.session = selected_session

        self.output(
            f"Selected past session: {record.session_id}"
        )
        self.output(
            f"Interface: {record.interface_name}"
        )
        self.output(
            "You can now choose option 3 to view its traffic summary."
        )

    def _list_interfaces(self) -> None:
        result = self.capture_service.list_interfaces()
        if result.status is not Status.OK:
            self.output(f"ERROR: interface: {result.detail}")
            return
        if not result.value:
            self.output("No network interfaces were found.")
            return
        self.output("Available interfaces: " + ", ".join(result.value))

    def _toggle_alerting(self) -> None:
        """Enable or disable alerting for the selected capture session."""
        if self.session is None:
            self.output("ERROR: Start a capture first.")
            return

        enabled = not self.alert_service.is_enabled(self.session)
        result = self.alert_service.set_enabled(self.session, enabled)

        if result.status is not Status.OK:
            self.output(f"ERROR: {result.detail}")
            return

        if enabled:
            self.output("Alerting enabled for this session.")
        else:
            self.output("Alerting disabled for this session.")

    def _view_alerts(self) -> None:
        """Display supported alerts for the selected capture session."""
        if self.session is None:
            self.output("ERROR: Start a capture first.")
            return

        result = self.alert_service.get_alerts(self.session)

        if result.status is not Status.OK:
            self.output(f"ERROR: {result.detail}")
            return

        alerts = result.value or []

        if not alerts:
            self.output("No supported scan alerts detected for this session.")
            return

        self.output(f"\nSupported alerts ({len(alerts)}):")

        for alert in alerts:
            self.output(
                f"[{alert.timestamp or 'Unknown time'}] "
                f"[{alert.priority}] {alert.note} | "
                f"Source: {alert.source or 'Unknown'} | "
                f"Destination: {alert.destination or 'Unknown'} | "
                f"Port: {alert.port or 'Unknown'}"
            )
            self.output(f"  Reason: {alert.reason}")

    def _start_capture(self) -> None:
        with self._state_lock:
            capture_active = self.capture_active
        if capture_active:
            self.output("ERROR: a capture is already running. View or stop it first.")
            return
        interface = self.input("Interface name (use option 1 to list): ").strip()
        duration = self.input(
            "Maximum duration in seconds (blank for manual stop): "
        ).strip()
        protocol_filter = self.input(
            "Protocol filter [tcp, udp, icmp] (blank for all traffic): "
        ).strip()
        result = self.capture_service.start_capture(
            interface,
            duration=duration or None,
            protocol_filter=protocol_filter or None,
        )
        if result.status is not Status.OK:
            self.output(f"ERROR: capture: {result.detail}")
            return
        session = result.value
        with self._state_lock:
            self.session = session
            self.capture_active = True
        options = []
        duration_seconds = getattr(session, "duration_seconds", None)
        protocol_filter = getattr(session, "protocol_filter", None)
        if duration_seconds is not None:
            options.append(f"maximum {duration_seconds} seconds")
        if protocol_filter is not None:
            options.append(f"{protocol_filter.upper()} only")
        suffix = f" ({', '.join(options)})." if options else "."
        self.output(f"Capture started on {session.interface_name}{suffix}")
        interval = self._summary_refresh_interval_seconds
        interval_unit = "second" if interval == 1 else "seconds"
        self.output(
            "Traffic summaries refresh automatically when new complete conn.log "
            f"records arrive (checked every {interval:g} {interval_unit})."
        )
        self._start_summary_refresh(session)

    def _view_summary(self) -> None:
        with self._state_lock:
            session = self.session
        if session is None:
            self.output("No session is selected. Start a capture first.")
            return
        with self._summary_lock:
            self._display_summary(session)

    def _display_summary(self, session: CaptureSession) -> None:
        result = self.summary_service.get_summary(session)
        if result.status is not Status.OK:
            detail = result.detail or result.status.value
            self.output(f"ERROR: summary: {detail}")
            return
        if result.value is None:
            self.output("ERROR: summary: summary service returned no summary.")
            return
        if result.detail:
            self.output(f"WARNING: summary: {result.detail}")
        self.output(render_summary(result.value))

    def _start_summary_refresh(self, session: CaptureSession) -> None:
        self._stop_summary_refresh()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._refresh_summary_loop,
            args=(session, stop_event),
            name=f"summary-refresh-{session.session_id[:8]}",
            daemon=True,
        )
        with self._state_lock:
            if self.session is not session or not self.capture_active:
                return
            self._summary_refresh_stop = stop_event
            self._summary_refresh_thread = thread
        thread.start()

    def _is_summary_refresh_current(
        self, session: CaptureSession, stop_event: threading.Event
    ) -> bool:
        with self._state_lock:
            return (
                self._summary_refresh_stop is stop_event
                and self.session is session
                and self.capture_active
            )

    def _write_refresh_output(
        self, session: CaptureSession, stop_event: threading.Event, message: str
    ) -> bool:
        with self._state_lock:
            if (
                self._summary_refresh_stop is not stop_event
                or self.session is not session
                or not self.capture_active
            ):
                return False
            self.output(message)
            return True

    def _stop_summary_refresh(self) -> None:
        with self._state_lock:
            stop_event = self._summary_refresh_stop
            thread = self._summary_refresh_thread
            if stop_event is not None:
                stop_event.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._state_lock:
            if self._summary_refresh_thread is thread:
                self._summary_refresh_stop = None
                self._summary_refresh_thread = None

    def _refresh_summary_loop(
        self, session: CaptureSession, stop_event: threading.Event
    ) -> None:
        previous_signature = None
        previous_error = None
        previous_detail = None
        while not stop_event.wait(self._summary_refresh_interval_seconds):
            if not self._is_summary_refresh_current(session, stop_event):
                return

            with self._summary_lock:
                result = self.summary_service.get_summary(session)
                if result.status is not Status.OK or result.value is None:
                    detail = result.detail or (
                        result.status.value
                        if result.status is not Status.OK
                        else "summary service returned no summary."
                    )
                    if detail != previous_error:
                        self._write_refresh_output(
                            session, stop_event, f"ERROR: summary: {detail}"
                        )
                    previous_error = detail
                    continue

                previous_error = None
                if result.detail and result.detail != previous_detail:
                    self._write_refresh_output(
                        session, stop_event, f"WARNING: summary: {result.detail}"
                    )
                previous_detail = result.detail

                summary = result.value
                signature = (
                    summary.connection_count,
                    tuple(sorted(summary.protocol_breakdown.items())),
                    tuple(summary.top_talkers),
                )
                if signature != previous_signature:
                    if not self._write_refresh_output(
                        session, stop_event, render_summary(summary)
                    ):
                        return
                    previous_signature = signature

    def _stop_capture(self) -> None:
        with self._state_lock:
            session = self.session
            capture_active = self.capture_active

        if session is None:
            self.output("No capture is running.")
            return

        if not capture_active:
            self.output(
                "No capture is running. Historical sessions cannot be stopped."
            )
            return

        status = self.capture_service.stop_capture(session.session_id)
        if status is not Status.OK:
            detail = getattr(self.capture_service, "last_error", "")
            message = f"ERROR: capture: could not stop session ({status.value})"
            if detail:
                message += f": {detail}"
            self.output(message + ".")
            return
        with self._state_lock:
            self.capture_active = False
            stop_event = self._summary_refresh_stop
            if stop_event is not None:
                stop_event.set()
        self._stop_summary_refresh()
        self.output("Capture stopped safely. The final summary is:")
        with self._summary_lock:
            result = self.summary_service.get_summary(session)
            if result.status is Status.OK:
                if result.value is None:
                    self.output("ERROR: summary: summary service returned no summary.")
                else:
                    if result.detail:
                        self.output(f"WARNING: summary: {result.detail}")
                    self.output(render_summary(result.value))
            else:
                detail = result.detail or result.status.value
                self.output(f"ERROR: summary: {detail}")

    def _on_capture_event(self, message: str) -> None:
        """Print monitor warnings immediately, even while input() is waiting."""
        if "stopping capture safely" in message.lower():
            with self._state_lock:
                self.capture_active = False
                stop_event = self._summary_refresh_stop
                if stop_event is not None:
                    stop_event.set()
        self.output(message)

    def _export_session(self) -> None:
        if self.selected_record is None:
            self.output("Browse and select a completed session first.")
            return

        destination = self.input("Enter export destination directory: ").strip()

        if not destination:
            self.output("Export cancelled.")
            return

        self.output("1. PCAP only")
        self.output("2. Zeek logs only")
        self.output("3. Both")

        choice = self.input("Choose export type: ").strip()

        if choice == "1":
            include_pcap, include_zeek = True, False
        elif choice == "2":
            include_pcap, include_zeek = False, True
        elif choice == "3":
            include_pcap, include_zeek = True, True
        else:
            self.output("Invalid choice.")
            return

        result = self.export_service.export_session(
            self.selected_record,
            destination,
            include_pcap=include_pcap,
            include_zeek_logs=include_zeek,
        )

        if result.status != Status.OK:
            self.output(f"Export failed: {result.detail}")
            return

        self.output("Export completed successfully!")
        for path in result.value:
            self.output(f"Exported: {path}")

if __name__ == "__main__":
    Dashboard().run()
