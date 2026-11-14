import os
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.types import Status
from services.export_service import ExportService
from services.session_index import SessionRecord


def make_record(tmp_path, session_id="session-1"):
    session_directory = tmp_path / "sessions" / session_id
    zeek_directory = session_directory / "zeek"
    zeek_directory.mkdir(parents=True)
    pcap_path = session_directory / "capture.pcap"
    pcap_path.write_bytes(b"synthetic pcap")
    log_path = zeek_directory / "conn.log"
    log_path.write_text("synthetic Zeek log\n", encoding="utf-8")
    started_at = datetime(2026, 11, 14, 8, 0, tzinfo=timezone.utc)
    return SessionRecord(
        session_id=session_id,
        interface_name="eth0",
        started_at=started_at,
        ended_at=started_at + timedelta(minutes=1),
        pcap_path=pcap_path,
        zeek_directory=zeek_directory,
        zeek_log_paths=(log_path,),
    )


def test_export_writes_selected_files_with_safe_names_and_contents(tmp_path):
    record = make_record(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()

    result = ExportService().export_session(record, destination)

    assert result.status is Status.OK
    exported = {path.name: path for path in result.value}
    pcap_path = exported["capture-session-1.pcap"]
    log_path = exported["zeek-session-1-1-conn.log"]
    assert pcap_path.read_bytes() == b"synthetic pcap"
    assert log_path.read_text(encoding="utf-8") == "synthetic Zeek log\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable")
def test_exported_files_are_owner_only_on_posix(tmp_path):
    record = make_record(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()

    result = ExportService().export_session(record, destination)

    assert result.status is Status.OK
    for path in result.value:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.geteuid()


@pytest.mark.parametrize(
    "session_id",
    ["../outside", "/absolute", "session.with.dot", "", None, 42],
)
def test_invalid_session_ids_are_rejected_without_writing_files(
    tmp_path, session_id
):
    record = replace(make_record(tmp_path), session_id=session_id)
    destination = tmp_path / "exports"
    destination.mkdir()

    result = ExportService().export_session(record, destination)

    assert result.status is Status.INVALID_INPUT
    assert list(destination.iterdir()) == []


@pytest.mark.parametrize("destination_value", ["", "   ", None])
def test_invalid_destinations_are_rejected_instead_of_defaulting_to_cwd(
    tmp_path, destination_value
):
    record = make_record(tmp_path)

    result = ExportService().export_session(record, destination_value)

    assert result.status is Status.INVALID_INPUT


def test_missing_or_non_directory_destinations_are_rejected(tmp_path):
    record = make_record(tmp_path)
    missing_destination = tmp_path / "missing"
    file_destination = tmp_path / "not-a-directory"
    file_destination.write_text("untouched", encoding="utf-8")

    missing_result = ExportService().export_session(record, missing_destination)
    file_result = ExportService().export_session(record, file_destination)

    assert missing_result.status is not Status.OK
    assert file_result.status is Status.INVALID_INPUT
    assert file_destination.read_text(encoding="utf-8") == "untouched"


def test_symlink_destination_is_rejected_without_writing_through_it(tmp_path):
    record = make_record(tmp_path)
    destination = tmp_path / "real-exports"
    destination.mkdir()
    symlink_destination = tmp_path / "export-link"
    try:
        symlink_destination.symlink_to(destination, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation is not supported: {error}")

    result = ExportService().export_session(record, symlink_destination)

    assert result.status is Status.INVALID_INPUT
    assert list(destination.iterdir()) == []


def test_symlinked_source_is_rejected_without_copying_its_target(tmp_path):
    record = make_record(tmp_path)
    outside_source = tmp_path / "outside.pcap"
    outside_source.write_bytes(b"outside")
    record.pcap_path.unlink()
    try:
        record.pcap_path.symlink_to(outside_source)
    except OSError as error:
        pytest.skip(f"symlink creation is not supported: {error}")
    destination = tmp_path / "exports"
    destination.mkdir()

    result = ExportService().export_session(
        record,
        destination,
        include_zeek_logs=False,
    )

    assert result.status is Status.IO_ERROR
    assert list(destination.iterdir()) == []
    assert outside_source.read_bytes() == b"outside"


def test_zeek_log_outside_session_directory_is_rejected(tmp_path):
    record = make_record(tmp_path)
    outside_log = tmp_path / "outside.log"
    outside_log.write_text("outside\n", encoding="utf-8")
    record = replace(record, zeek_log_paths=(outside_log,))
    destination = tmp_path / "exports"
    destination.mkdir()

    result = ExportService().export_session(
        record,
        destination,
        include_pcap=False,
    )

    assert result.status is Status.IO_ERROR
    assert list(destination.iterdir()) == []
    assert outside_log.read_text(encoding="utf-8") == "outside\n"


def test_existing_export_is_not_overwritten(tmp_path):
    record = make_record(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()
    existing_export = destination / "capture-session-1.pcap"
    existing_export.write_bytes(b"keep existing contents")

    result = ExportService().export_session(
        record,
        destination,
        include_zeek_logs=False,
    )

    assert result.status is Status.IO_ERROR
    assert existing_export.read_bytes() == b"keep existing contents"
    assert list(destination.iterdir()) == [existing_export]


def test_symlink_at_export_filename_is_not_followed_or_overwritten(tmp_path):
    record = make_record(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()
    outside_target = tmp_path / "keep.txt"
    outside_target.write_text("keep", encoding="utf-8")
    export_link = destination / "capture-session-1.pcap"
    try:
        export_link.symlink_to(outside_target)
    except OSError as error:
        pytest.skip(f"symlink creation is not supported: {error}")

    result = ExportService().export_session(
        record,
        destination,
        include_zeek_logs=False,
    )

    assert result.status is Status.IO_ERROR
    assert outside_target.read_text(encoding="utf-8") == "keep"
    assert export_link.is_symlink()

