from __future__ import annotations

import csv
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Protocol

from ..forms import ParsedFilters

SUPPORTED_EXTENSIONS = {".json", ".txt", ".log", ".csv", ".db", ".sqlite", ".msg"}
DEFAULT_TIMEZONE = timezone.utc


class ExtractionError(RuntimeError):
    """Raised when the extraction pipeline fails."""


@dataclass
class Message:
    talker: str
    sender: str
    timestamp: datetime | None
    message_type: str
    content: str
    file_path: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "talker": self.talker,
            "sender": self.sender,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "message_type": self.message_type,
            "content": self.content,
            "file_path": self.file_path,
            "metadata": self.metadata,
        }


@dataclass
class ExtractionStats:
    total_messages: int
    matched_messages: int
    scanned_files: int
    parsed_files: int
    failed_files: list[str]
    contacts_found: list[str]
    earliest_timestamp: str | None
    latest_timestamp: str | None


@dataclass
class ExtractionResult:
    messages: list[Message]
    stats: ExtractionStats


class Parser(Protocol):
    def can_parse(self, path: Path) -> bool:
        ...

    def parse(self, path: Path) -> Iterable[Message]:
        ...


class JSONParser:
    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == ".json"

    def parse(self, path: Path) -> Iterable[Message]:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            records = data.get("messages") or []
        else:
            records = data
        for index, item in enumerate(records):
            if not isinstance(item, dict):
                continue
            timestamp = _coerce_timestamp(item.get("timestamp"))
            talker = str(item.get("talker") or item.get("chat") or "")
            sender = str(item.get("sender") or item.get("from") or talker)
            message_type = str(item.get("message_type") or item.get("type") or "text")
            content = str(item.get("content") or item.get("body") or "")
            yield Message(
                talker=talker,
                sender=sender,
                timestamp=timestamp,
                message_type=message_type.lower(),
                content=content,
                file_path=str(path),
                metadata={"index": str(index)},
            )


class TextParser:
    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in {".txt", ".log"}

    def parse(self, path: Path) -> Iterable[Message]:
        with path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                line = line.strip()
                if not line:
                    continue
                timestamp, talker, sender, body = _split_text_line(line)
                yield Message(
                    talker=talker,
                    sender=sender,
                    timestamp=timestamp,
                    message_type="text",
                    content=body,
                    file_path=str(path),
                    metadata={"line": str(index + 1)},
                )


class SQLiteParser:
    TABLE_CANDIDATES = (
        "message",
        "Message",
        "ChatMsg",
    )

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in {".db", ".sqlite", ".msg"}

    def parse(self, path: Path) -> Iterable[Message]:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            cursor = connection.cursor()
            table = self._find_table(cursor)
            if not table:
                return []
            query = (
                "SELECT talker, createTime, type, subType, strContent, bytesExtra, sender "
                f"FROM {table}"
            )
            try:
                cursor.execute(query)
            except sqlite3.OperationalError:
                query = (
                    "SELECT talker, createTime, type, "
                    "NULL AS subType, strContent, NULL AS bytesExtra, sender "
                    f"FROM {table}"
                )
                cursor.execute(query)
            columns = [description[0] for description in cursor.description]
            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                talker = str(record.get("talker") or record.get("Talker") or "")
                sender = str(record.get("sender") or talker)
                message_type = record.get("type")
                content = record.get("strContent") or ""
                timestamp = _coerce_sqlite_timestamp(record.get("createTime"))
                metadata = {
                    key: str(value)
                    for key, value in record.items()
                    if key not in {"talker", "createTime", "type", "strContent", "sender"}
                    and value is not None
                }
                yield Message(
                    talker=talker,
                    sender=sender,
                    timestamp=timestamp,
                    message_type=str(message_type).lower() if message_type is not None else "unknown",
                    content=str(content),
                    file_path=str(path),
                    metadata=metadata,
                )
        finally:
            connection.close()

    def _find_table(self, cursor: sqlite3.Cursor) -> str | None:
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ({})".format(
                ",".join(f"'{table}'" for table in self.TABLE_CANDIDATES)
            )
        )
        row = cursor.fetchone()
        if row:
            return row[0]
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        row = cursor.fetchone()
        return row[0] if row else None


class CSVParser:
    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == ".csv"

    def parse(self, path: Path) -> Iterable[Message]:
        with path.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                talker = row.get("talker") or row.get("chat") or ""
                sender = row.get("sender") or talker
                message_type = row.get("message_type") or row.get("type") or "text"
                content = row.get("content") or row.get("body") or ""
                timestamp = _coerce_timestamp(row.get("timestamp"))
                yield Message(
                    talker=str(talker),
                    sender=str(sender),
                    timestamp=timestamp,
                    message_type=str(message_type).lower(),
                    content=str(content),
                    file_path=str(path),
                    metadata={"index": str(index)},
                )


class ExtractionService:
    def __init__(self, parsers: Iterable[Parser] | None = None) -> None:
        self.parsers: tuple[Parser, ...] = tuple(
            parsers or (JSONParser(), CSVParser(), SQLiteParser(), TextParser())
        )

    def extract(self, filters: ParsedFilters) -> ExtractionResult:
        if not filters.base_dir.exists():
            raise ExtractionError("提供的目录不存在。")
        candidate_files = list(self._iter_files(filters.base_dir, filters.include_subdirectories))
        if not candidate_files:
            raise ExtractionError("目录中未找到可解析的聊天记录文件。")

        all_messages: list[Message] = []
        failed_files: list[str] = []
        contacts: set[str] = set()
        parsed_files = 0

        for file_path in candidate_files:
            parser = self._select_parser(file_path)
            if not parser:
                continue
            try:
                parsed = list(parser.parse(file_path))
            except (sqlite3.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
                failed_files.append(f"{file_path.name}: {exc}")
                continue
            if parsed:
                parsed_files += 1
                for message in parsed:
                    if message.talker:
                        contacts.add(message.talker)
                all_messages.extend(parsed)

        if not all_messages:
            error_message = "未能解析出任何聊天记录。"
            if failed_files:
                error_message += " 失败文件: " + "; ".join(failed_files[:5])
            raise ExtractionError(error_message)

        matched_messages = self._apply_filters(all_messages, filters)
        matched_messages.sort(key=_message_sort_key, reverse=True)
        limited_messages = matched_messages[: filters.limit]

        stats = self._build_stats(
            all_messages=all_messages,
            matched_messages=matched_messages,
            candidate_files=candidate_files,
            parsed_files=parsed_files,
            failed_files=failed_files,
            contacts=sorted(contacts),
        )
        return ExtractionResult(messages=limited_messages, stats=stats)

    def _iter_files(self, base_dir: Path, recursive: bool) -> Iterator[Path]:
        if recursive:
            iterator = base_dir.rglob("*")
        else:
            iterator = base_dir.glob("*")
        for path in iterator:
            if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield path

    def _select_parser(self, path: Path) -> Parser | None:
        for parser in self.parsers:
            try:
                if parser.can_parse(path):
                    return parser
            except Exception:  # pragma: no cover - defensive programming
                continue
        return None

    def _apply_filters(self, messages: list[Message], filters: ParsedFilters) -> list[Message]:
        contacts_filter = [item.lower() for item in filters.contacts]
        message_types_filter = [item.lower() for item in filters.message_types]
        start = _normalize_datetime(filters.start_time)
        end = _normalize_datetime(filters.end_time)

        def matches(message: Message) -> bool:
            if contacts_filter:
                candidate = message.talker.lower()
                if all(filter_value not in candidate for filter_value in contacts_filter):
                    return False
            if message_types_filter:
                if message.message_type.lower() not in message_types_filter:
                    return False
            timestamp = _normalize_datetime(message.timestamp)
            if start and timestamp and timestamp < start:
                return False
            if end and timestamp and timestamp > end:
                return False
            return True

        return [message for message in messages if matches(message)]

    def _build_stats(
        self,
        *,
        all_messages: list[Message],
        matched_messages: list[Message],
        candidate_files: list[Path],
        parsed_files: int,
        failed_files: list[str],
        contacts: list[str],
    ) -> ExtractionStats:
        timestamps = [message.timestamp for message in all_messages if message.timestamp]
        earliest = min(timestamps).isoformat() if timestamps else None
        latest = max(timestamps).isoformat() if timestamps else None
        return ExtractionStats(
            total_messages=len(all_messages),
            matched_messages=len(matched_messages),
            scanned_files=len(candidate_files),
            parsed_files=parsed_files,
            failed_files=failed_files,
            contacts_found=contacts,
            earliest_timestamp=earliest,
            latest_timestamp=latest,
        )


def _coerce_timestamp(raw: object) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return _normalize_datetime(raw)
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=DEFAULT_TIMEZONE)
    if isinstance(raw, str):
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M",
            "%Y.%m.%d %H:%M:%S",
            "%Y.%m.%d %H:%M",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=DEFAULT_TIMEZONE)
            except ValueError:
                continue
    return None


def _coerce_sqlite_timestamp(raw: object) -> datetime | None:
    timestamp = _coerce_timestamp(raw)
    if timestamp:
        return timestamp
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw) / 1000, tz=DEFAULT_TIMEZONE)
    if isinstance(raw, str) and raw.isdigit():
        value = int(raw)
        if len(raw) > 11:
            return datetime.fromtimestamp(value / 1000, tz=DEFAULT_TIMEZONE)
        return datetime.fromtimestamp(value, tz=DEFAULT_TIMEZONE)
    return None


def _split_text_line(line: str) -> tuple[datetime | None, str, str, str]:
    parts = line.split("-", 1)
    if len(parts) == 2:
        timestamp = _coerce_timestamp(parts[0].strip())
        remainder = parts[1].strip()
    else:
        timestamp = None
        remainder = line

    talker = ""
    sender = ""
    body = remainder

    if ":" in remainder:
        header, body = remainder.split(":", 1)
        body = body.strip()
        if "(" in header and header.endswith(")"):
            talker_part, sender_part = header[:-1].split("(", 1)
            talker = talker_part.strip()
            sender = sender_part.strip()
        else:
            talker = header.strip()
            sender = talker
    return timestamp, talker, sender or talker, body


def _message_sort_key(message: Message) -> tuple:
    timestamp = _normalize_datetime(message.timestamp) or datetime.fromtimestamp(
        0, tz=DEFAULT_TIMEZONE
    )
    return (timestamp, message.talker, message.sender)


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=DEFAULT_TIMEZONE)
    return value.astimezone(DEFAULT_TIMEZONE)
