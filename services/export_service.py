
"""Safely export PCAP captures and Zeek logs from completed sessions."""

import os
import re
import shutil
from pathlib import Path

from core.types import Result, Status
from services.session_index import SessionRecord


class ExportService:
    """Export selected session artifacts into a user-selected directory."""

    def export_session(
        self,
        record: SessionRecord,
        destination: Path | str,
        include_pcap: bool = True,
        include_zeek_logs: bool = True,
    ) -> Result[list[Path]]:
        if not isinstance(record, SessionRecord):
            return Result(Status.INVALID_INPUT, detail="Invalid session record.")

        if not isinstance(include_pcap, bool) or not isinstance(
            include_zeek_logs, bool
        ):
            return Result(Status.INVALID_INPUT, detail="Export selections must be boolean.")

        if not include_pcap and not include_zeek_logs:
            return Result(Status.INVALID_INPUT, detail="Select PCAP, Zeek logs, or both.")

        if not re.fullmatch(r"[A-Za-z0-9_-]+", record.session_id):
            return Result(Status.INVALID_INPUT, detail="Unsafe session ID.")

        try:
            destination_path = Path(destination).expanduser()

            if destination_path.is_symlink():
                return Result(Status.INVALID_INPUT, detail="Symbolic-link destinations are not allowed.")

            destination_path = destination_path.resolve(strict=True)

            if not destination_path.is_dir():
                return Result(Status.INVALID_INPUT, detail="Destination must be an existing directory.")

            sources: list[tuple[Path, str]] = []

            if include_pcap:
                sources.append(
                    (
                        self._validate_source(record.pcap_path, record.pcap_path.parent),
                        f"capture-{record.session_id}.pcap",
                    )
                )

            if include_zeek_logs:
                for index, log_path in enumerate(record.zeek_log_paths, start=1):
                    source = self._validate_source(log_path, record.zeek_directory)
                    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", source.name)
                    sources.append(
                        (
                            source,
                            f"zeek-{record.session_id}-{index}-{safe_name}",
                        )
                    )

            if not sources:
                return Result(Status.INVALID_INPUT, detail="No files are available to export.")

            exported: list[Path] = []

            for source, filename in sources:
                target = destination_path / filename

                if target.exists() or target.is_symlink():
                    raise FileExistsError(f"Export file already exists: {target.name}")

                self._copy_without_overwrite(source, target)
                exported.append(target)

            return Result(Status.OK, value=exported)

        except PermissionError as error:
            return Result(Status.PERMISSION_ERROR, detail=str(error))
        except (OSError, ValueError, TypeError) as error:
            return Result(Status.IO_ERROR, detail=f"Export failed: {error}")

    @staticmethod
    def _validate_source(source: Path, allowed_directory: Path) -> Path:
        source = Path(source)
        allowed_directory = Path(allowed_directory)

        if source.is_symlink() or allowed_directory.is_symlink():
            raise ValueError("Symbolic-link source paths are not allowed.")

        resolved_source = source.resolve(strict=True)
        resolved_directory = allowed_directory.resolve(strict=True)

        if not resolved_source.is_relative_to(resolved_directory):
            raise ValueError("Source file is outside its session directory.")

        if not resolved_source.is_file():
            raise ValueError("Export source is not a regular file.")

        return resolved_source

    @staticmethod
    def _copy_without_overwrite(source: Path, target: Path) -> None:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output)
        except Exception:
            target.unlink(missing_ok=True)
            raise