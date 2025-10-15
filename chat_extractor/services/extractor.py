from __future__ import annotations

import csv
import json
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Protocol

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
    conversation: str = ""
    direction: str = "unknown"

    def __post_init__(self) -> None:
        base = self.talker.strip() if self.talker else ""
        sender = self.sender.strip() if self.sender else ""
        if not base and sender:
            base = sender
        self.talker = base or sender
        self.sender = sender or base
        self.conversation = (self.conversation or self.talker or self.sender or "").strip()
        if self.direction == "unknown":
            self.direction = _infer_direction(self.metadata.get("is_send"))

    def to_dict(self) -> dict[str, object]:
        return {
            "talker": self.talker,
            "sender": self.sender,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "message_type": self.message_type,
            "content": self.content,
            "file_path": self.file_path,
            "metadata": self.metadata,
            "conversation": self.conversation,
            "direction": self.direction,
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
    top_contacts: list[dict[str, object]]
    message_type_breakdown: list[dict[str, object]]
    daily_breakdown: list[dict[str, object]]


@dataclass
class ExtractionResult:
    messages: list[Message]
    stats: ExtractionStats
    grouped_threads: list["ConversationGroup"]


@dataclass
class ConversationGroup:
    name: str
    count: int
    messages: list[Message]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "count": self.count,
            "messages": [message.to_dict() for message in self.messages],
        }


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
            direction_source = (
                item.get("direction")
                or item.get("is_send")
                or item.get("issend")
                or item.get("isSend")
            )
            metadata = {"index": str(index)}
            if direction_source is not None:
                metadata["is_send"] = str(direction_source)
            yield Message(
                talker=talker,
                sender=sender,
                timestamp=timestamp,
                message_type=message_type.lower(),
                content=content,
                file_path=str(path),
                metadata=metadata,
                conversation=str(item.get("conversation") or talker or sender),
                direction=_infer_direction(direction_source),
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
                    conversation=talker or sender,
                    direction="unknown",
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
                direction_source = (
                    record.get("isSend")
                    or record.get("issend")
                    or record.get("is_send")
                    or record.get("IsSend")
                )
                metadata = {
                    key: str(value)
                    for key, value in record.items()
                    if key not in {"talker", "createTime", "type", "strContent", "sender"}
                    and value is not None
                }
                if direction_source is not None:
                    metadata.setdefault("is_send", str(direction_source))
                yield Message(
                    talker=talker,
                    sender=sender,
                    timestamp=timestamp,
                    message_type=str(message_type).lower() if message_type is not None else "unknown",
                    content=str(content),
                    file_path=str(path),
                    metadata=metadata,
                    conversation=metadata.get("chatroom") or talker,
                    direction=_infer_direction(direction_source),
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
                direction_source = row.get("direction") or row.get("is_send") or row.get("issend")
                metadata = {"index": str(index)}
                if direction_source is not None:
                    metadata["is_send"] = str(direction_source)
                yield Message(
                    talker=str(talker),
                    sender=str(sender),
                    timestamp=timestamp,
                    message_type=str(message_type).lower(),
                    content=str(content),
                    file_path=str(path),
                    metadata=metadata,
                    conversation=row.get("conversation") or talker or sender,
                    direction=_infer_direction(direction_source),
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
                    if message.conversation:
                        contacts.add(message.conversation)
                all_messages.extend(parsed)

        if not all_messages:
            error_message = "未能解析出任何聊天记录。"
            if failed_files:
                error_message += " 失败文件: " + "; ".join(failed_files[:5])
            raise ExtractionError(error_message)

        matched_messages = self._apply_filters(all_messages, filters)
        matched_messages.sort(key=_message_sort_key, reverse=True)
        limited_messages = matched_messages[: filters.limit]
        per_thread_limit = min(200, max(filters.limit, 50))

        stats = self._build_stats(
            all_messages=all_messages,
            matched_messages=matched_messages,
            candidate_files=candidate_files,
            parsed_files=parsed_files,
            failed_files=failed_files,
            contacts=sorted(contacts),
        )
        grouped_threads = self._group_messages(
            matched_messages,
            per_thread_limit=per_thread_limit,
            max_threads=20,
        )
        return ExtractionResult(messages=limited_messages, stats=stats, grouped_threads=grouped_threads)

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
                haystack = " ".join(
                    part
                    for part in [message.conversation, message.talker, message.sender]
                    if part
                ).lower()
                if all(filter_value not in haystack for filter_value in contacts_filter):
                    return False
            if message_types_filter:
                if (message.message_type or "").lower() not in message_types_filter:
                    return False
            timestamp = _normalize_datetime(message.timestamp)
            if start and timestamp and timestamp < start:
                return False
            if end and timestamp and timestamp > end:
                return False
            return True

        return [message for message in messages if matches(message)]

    def _group_messages(
        self,
        messages: list[Message],
        *,
        per_thread_limit: int = 50,
        max_threads: int = 20,
    ) -> list[ConversationGroup]:
        grouped: dict[str, list[Message]] = {}
        for message in messages:
            key = message.conversation or message.talker or message.sender or "未命名会话"
            grouped.setdefault(key, []).append(message)

        sorted_groups = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0].lower()))
        produced: list[ConversationGroup] = []
        per_thread_limit = max(per_thread_limit, 1)
        for name, group_messages in sorted_groups[:max_threads]:
            ordered = sorted(
                group_messages,
                key=lambda msg: _normalize_datetime(msg.timestamp)
                or datetime.fromtimestamp(0, tz=DEFAULT_TIMEZONE),
            )
            trimmed = ordered[-per_thread_limit:]
            produced.append(ConversationGroup(name=name, count=len(group_messages), messages=trimmed))
        return produced

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

        contact_counter: Counter[str] = Counter(
            message.conversation for message in all_messages if message.conversation
        )
        type_counter: Counter[str] = Counter(
            (message.message_type or "unknown").lower() for message in all_messages
        )
        daily_counter: Counter[str] = Counter()
        for message in all_messages:
            normalized = _normalize_datetime(message.timestamp)
            if normalized:
                daily_counter[normalized.date().isoformat()] += 1

        return ExtractionStats(
            total_messages=len(all_messages),
            matched_messages=len(matched_messages),
            scanned_files=len(candidate_files),
            parsed_files=parsed_files,
            failed_files=failed_files,
            contacts_found=contacts,
            earliest_timestamp=earliest,
            latest_timestamp=latest,
            top_contacts=_format_counter(contact_counter, limit=10),
            message_type_breakdown=_format_counter(type_counter, limit=None),
            daily_breakdown=_format_counter(daily_counter, limit=None, sort_key=lambda item: item[0]),
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


def _format_counter(
    counter: Counter[str], *, limit: int | None, sort_key: Callable[[tuple[str, int]], object] | None = None
) -> list[dict[str, object]]:
    items = list(counter.items())
    if not items:
        return []
    if sort_key:
        items.sort(key=sort_key)
    else:
        items.sort(key=lambda pair: (-pair[1], pair[0]))
    if limit is not None:
        items = items[:limit]
    return [{"label": label, "count": count} for label, count in items]


def _infer_direction(raw: object | None) -> str:
    if raw is None:
        return "unknown"
    if isinstance(raw, bool):
        return "outgoing" if raw else "incoming"
    if isinstance(raw, (int, float)):
        return "outgoing" if int(raw) == 1 else "incoming"
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in {"1", "true", "sent", "out", "outgoing", "self"}:
            return "outgoing"
        if normalized in {"0", "false", "received", "in", "incoming", "other"}:
            return "incoming"
    return "unknown"
