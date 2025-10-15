from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Protocol
from urllib.parse import urlparse

from html import unescape
from xml.etree import ElementTree as ET

from ..forms import ParsedFilters
from .wechat_crypto import SQLCipherSupportError
from .wechat_sqlcipher import WeChatSQLCipherHelper

SUPPORTED_EXTENSIONS = {
    ".json",
    ".txt",
    ".log",
    ".csv",
    ".db",
    ".sqlite",
    ".msg",
    ".xml",
    ".html",
    ".htm",
}
DEFAULT_TIMEZONE = timezone.utc
MESSAGE_TYPE_LABELS: dict[str, str] = {
    "text": "文本",
    "image": "图片",
    "video": "视频",
    "short_video": "小视频",
    "sticker": "表情",
    "file": "文件",
    "link": "链接",
    "app": "小程序",
    "location": "位置",
    "contact_card": "名片",
    "name_card": "名片",
    "friend_request": "好友请求",
    "system": "系统",
    "recall": "撤回",
    "call": "通话",
    "voice": "语音",
    "rich_media": "富媒体",
    "unknown": "未知",
}
MESSAGE_TYPE_PLACEHOLDERS: dict[str, str] = {
    "image": "[图片消息]",
    "video": "[视频消息]",
    "short_video": "[小视频消息]",
    "voice": "[语音消息]",
    "sticker": "[表情消息]",
    "file": "[文件消息]",
    "link": "[链接消息]",
    "app": "[卡片消息]",
    "location": "[位置消息]",
    "contact_card": "[名片消息]",
    "name_card": "[名片消息]",
    "friend_request": "[好友请求]",
    "system": "[系统通知]",
    "recall": "[撤回消息]",
}


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
    display_type: str = ""
    display_content: str = ""
    display_meta: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # 规范化 talker 和 sender
        talker = self.talker.strip() if self.talker else ""
        sender = self.sender.strip() if self.sender else ""
        
        # talker 是会话对象(可能是对方微信ID或群ID)
        # sender 是消息发送人
        if not talker and sender:
            talker = sender
        if not sender and talker:
            sender = talker
            
        self.talker = talker or sender
        self.sender = sender or talker
        
        # conversation 是显示用的会话名称
        # 优先使用已设置的 conversation,否则使用 talker
        if not self.conversation:
            self.conversation = talker or sender
        self.conversation = self.conversation.strip()
        
        # 对于群聊,从 metadata 中提取群名称
        is_chatroom = self.metadata.get("is_chatroom") == "true"
        if is_chatroom and self.conversation.endswith("@chatroom"):
            # 群聊ID格式: xxxxx@chatroom
            # 暂时保留原始ID,后续可以通过群聊名称映射表获取真实群名
            pass
        
        # 规范化消息类型
        self.message_type = _normalize_message_type(self.message_type)
        
        # 推断消息方向
        if self.direction == "unknown":
            self.direction = _infer_direction(self.metadata.get("is_send") or self.metadata.get("isSender"))
        
        # 生成显示类型和内容
        self.display_type = MESSAGE_TYPE_LABELS.get(self.message_type, self.message_type or "未知")
        self.display_content = _derive_display_content(self.message_type, self.content, self.metadata)
        
        # 如果原始content为空,使用display_content
        if not self.content:
            self.content = self.display_content
        
        # 构建多媒体元数据
        self.display_meta = _build_display_meta(
            self.message_type,
            self.content,
            self.metadata,
            direction=self.direction,
        )

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
            "display_type": self.display_type,
            "display_content": self.display_content,
            "display_meta": self.display_meta,
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
class ConversationDay:
    date: str
    messages: list[Message]

    @property
    def count(self) -> int:
        return len(self.messages)

    def to_dict(self) -> dict[str, object]:
        return {
            "date": self.date,
            "count": self.count,
            "messages": [message.to_dict() for message in self.messages],
        }


@dataclass
class ConversationGroup:
    name: str
    count: int
    messages: list[Message]
    first_timestamp: str | None
    last_timestamp: str | None
    days: list[ConversationDay]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "count": self.count,
            "messages": [message.to_dict() for message in self.messages],
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "days": [day.to_dict() for day in self.days],
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
            message_type = _normalize_message_type(item.get("message_type") or item.get("type") or "text")
            content = str(item.get("content") or item.get("body") or "")
            direction_source = (
                item.get("direction")
                or item.get("is_send")
                or item.get("issend")
                or item.get("isSend")
            )
            metadata = {"index": str(index)}
            metadata.update(_extract_metadata_fields(item))
            if direction_source is not None:
                metadata["is_send"] = str(direction_source)
            yield Message(
                talker=talker,
                sender=sender,
                timestamp=timestamp,
                message_type=message_type,
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
                    conversation=(talker or path.stem or sender),
                    direction="unknown",
                )


class XMLParser:
    PREFERRED_TAGS = (
        "message",
        "item",
        "record",
        "chat",
    )

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == ".xml"

    def parse(self, path: Path) -> Iterable[Message]:
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            return []

        root = tree.getroot()
        nodes: list[ET.Element] = []
        for tag in self.PREFERRED_TAGS:
            nodes = list(root.findall(f".//{tag}"))
            if nodes:
                break
        if not nodes:
            nodes = list(root.iter())

        known_tags = {
            "talker",
            "chat",
            "conversation",
            "sender",
            "from",
            "timestamp",
            "time",
            "createTime",
            "message_type",
            "type",
            "msgType",
            "content",
            "body",
            "text",
            "is_send",
            "issend",
            "direction",
        }

        for index, node in enumerate(nodes):
            children = {child.tag: (child.text.strip() if child.text else "") for child in node if child.text}

            def fetch(*names: str) -> str:
                for name in names:
                    if name in children and children[name]:
                        return children[name]
                    element = node.find(name)
                    if element is not None and (element.text or "").strip():
                        return element.text.strip()
                return ""

            talker = fetch("talker", "chat", "conversation")
            sender = fetch("sender", "from", "author") or talker
            timestamp_raw = fetch("timestamp", "time", "createTime")
            timestamp = _coerce_timestamp(timestamp_raw)
            message_type_raw = fetch("message_type", "type", "msgType") or "text"
            message_type = _normalize_message_type(message_type_raw)
            content = fetch("content", "body", "text")
            direction_source = fetch("direction", "is_send", "issend") or None

            metadata = {key: value for key, value in node.attrib.items()}
            metadata["index"] = str(index)
            for key, value in children.items():
                if key not in known_tags and value:
                    metadata[key] = value

            conversation = fetch("conversation", "talker", "chat") or talker or sender or path.stem

            yield Message(
                talker=talker,
                sender=sender,
                timestamp=timestamp,
                message_type=message_type,
                content=content,
                file_path=str(path),
                metadata=metadata,
                conversation=conversation,
                direction=_infer_direction(direction_source),
            )


class HTMLParser:
    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in {".html", ".htm"}

    def parse(self, path: Path) -> Iterable[Message]:
        raw_text = path.read_text(encoding="utf-8", errors="ignore")
        title_match = re.search(r"<title>(.*?)</title>", raw_text, flags=re.IGNORECASE | re.DOTALL)
        conversation_name = unescape(title_match.group(1).strip()) if title_match else path.stem

        stripped = re.sub(r"<(script|style)[^>]*>.*?</\\1>", " ", raw_text, flags=re.IGNORECASE | re.DOTALL)
        stripped = re.sub(r"<[^>]+>", " ", stripped)
        lines = [unescape(part.strip()) for part in stripped.splitlines() if part.strip()]

        for index, line in enumerate(lines):
            timestamp, talker, sender, body = _split_text_line(line)
            if not any([timestamp, talker, sender]) and ":" in line:
                parts = line.split(":", 1)
                sender = parts[0].strip()
                body = parts[1].strip()
            yield Message(
                talker=talker,
                sender=sender,
                timestamp=timestamp,
                message_type="text",
                content=body,
                file_path=str(path),
                metadata={"line": str(index + 1)},
                conversation=talker or conversation_name or sender,
                direction="unknown",
            )


class SQLiteParser:
    TABLE_CANDIDATES = (
        "MSG",  # 真实微信数据库表名
        "message",
        "Message",
        "ChatMsg",
    )

    def __init__(self, sqlcipher_helper: WeChatSQLCipherHelper | None = None) -> None:
        self._sqlcipher_helper = sqlcipher_helper or WeChatSQLCipherHelper()
        self._filters: ParsedFilters | None = None

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in {".db", ".sqlite", ".msg"}

    def set_filter_context(self, filters: ParsedFilters) -> None:
        self._filters = filters
        self._sqlcipher_helper.set_manual_key(filters.wechat_db_key)

    def parse(self, path: Path) -> Iterable[Message]:
        connection = self._sqlcipher_helper.open_connection(path, self._filters)
        try:
            cursor = connection.cursor()
            table = self._find_table(cursor)
            if not table:
                return []
            
            # 尝试使用微信真实数据库的字段名称 (参考 wechatDataBackup)
            queries_to_try = [
                # 微信真实数据库格式: MSG 表包含 StrTalker, StrContent, IsSender, CreateTime
                f"""SELECT 
                    ifnull(StrTalker, '') as talker,
                    CreateTime as createTime,
                    Type as type,
                    SubType as subType,
                    ifnull(StrContent, '') as strContent,
                    ifnull(BytesExtra, '') as bytesExtra,
                    IsSender as isSender,
                    localId,
                    MsgSvrID as msgSvrId,
                    ifnull(CompressContent, '') as compressContent
                FROM {table}""",
                # 标准格式
                f"""SELECT 
                    talker, 
                    createTime, 
                    type, 
                    subType, 
                    strContent, 
                    bytesExtra, 
                    sender,
                    isSend
                FROM {table}""",
                # 简化格式
                f"""SELECT 
                    talker, 
                    createTime, 
                    type, 
                    NULL AS subType, 
                    strContent, 
                    NULL AS bytesExtra, 
                    sender,
                    isSend
                FROM {table}""",
            ]
            
            cursor_result = None
            for query in queries_to_try:
                try:
                    cursor.execute(query)
                    cursor_result = cursor
                    break
                except sqlite3.OperationalError:
                    continue
            
            if not cursor_result:
                return []
            
            columns = [description[0] for description in cursor.description]
            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                
                # 兼容多种字段名称
                talker = str(
                    record.get("talker") 
                    or record.get("Talker") 
                    or record.get("StrTalker") 
                    or record.get("strtalker")
                    or ""
                )
                
                sender = str(
                    record.get("sender")
                    or record.get("Sender") 
                    or talker
                )
                
                # 从 talker 中提取实际的会话对象
                # 对于群聊，格式可能是 "群ID@chatroom"
                conversation = talker
                
                message_type = _resolve_message_type(
                    record.get("type") or record.get("Type"),
                    record.get("subType") or record.get("SubType")
                )
                
                content = str(
                    record.get("strContent")
                    or record.get("StrContent") 
                    or record.get("content")
                    or ""
                )
                
                timestamp = _coerce_sqlite_timestamp(
                    record.get("createTime") 
                    or record.get("CreateTime")
                    or record.get("timestamp")
                )
                
                direction_source = (
                    record.get("isSender")
                    or record.get("IsSender")
                    or record.get("isSend")
                    or record.get("issend")
                    or record.get("is_send")
                    or record.get("IsSend")
                )
                
                # 提取所有元数据
                metadata = {}
                skip_keys = {
                    "talker", "Talker", "StrTalker", "strtalker",
                    "createTime", "CreateTime", "timestamp",
                    "type", "Type",
                    "strContent", "StrContent", "content",
                    "sender", "Sender",
                }
                for key, value in record.items():
                    if key not in skip_keys and value is not None:
                        metadata[key] = _stringify_metadata_value(value)
                
                if direction_source is not None:
                    metadata.setdefault("is_send", str(direction_source))
                
                # 提取压缩内容和额外字节
                if "compressContent" in record or "CompressContent" in record:
                    metadata["compressContent"] = _stringify_metadata_value(
                        record.get("compressContent") or record.get("CompressContent")
                    )
                
                if "bytesExtra" in record or "BytesExtra" in record:
                    metadata["bytesExtra"] = _stringify_metadata_value(
                        record.get("bytesExtra") or record.get("BytesExtra")
                    )
                
                # 标记是否为群聊
                is_chatroom = conversation.endswith("@chatroom")
                if is_chatroom:
                    metadata["is_chatroom"] = "true"
                
                yield Message(
                    talker=talker,
                    sender=sender,
                    timestamp=timestamp,
                    message_type=message_type,
                    content=content,
                    file_path=str(path),
                    metadata=metadata,
                    conversation=conversation,
                    direction=_infer_direction(direction_source),
                )
        finally:
            connection.close()

    def _find_table(self, cursor: sqlite3.Cursor) -> str | None:
        # 优先查找候选表名
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ({})".format(
                ",".join(f"'{table}'" for table in self.TABLE_CANDIDATES)
            )
        )
        row = cursor.fetchone()
        if row:
            return row[0]
        
        # 如果没有找到，返回第一个表
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
                message_type = _normalize_message_type(row.get("message_type") or row.get("type") or "text")
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
                    message_type=message_type,
                    content=str(content),
                    file_path=str(path),
                    metadata=metadata,
                    conversation=row.get("conversation") or talker or sender,
                    direction=_infer_direction(direction_source),
                )


class ExtractionService:
    def __init__(self, parsers: Iterable[Parser] | None = None) -> None:
        self._sqlcipher_helper = WeChatSQLCipherHelper()
        self.parsers: tuple[Parser, ...] = tuple(
            parsers
            or (
                JSONParser(),
                XMLParser(),
                HTMLParser(),
                CSVParser(),
                SQLiteParser(self._sqlcipher_helper),
                TextParser(),
            )
        )

    def extract(self, filters: ParsedFilters) -> ExtractionResult:
        if not filters.base_dir.exists():
            raise ExtractionError("提供的目录不存在。")
        candidate_files = list(self._iter_files(filters.base_dir, filters.include_subdirectories))
        if not candidate_files:
            raise ExtractionError("目录中未找到可解析的聊天记录文件。")

        for parser in self.parsers:
            setter = getattr(parser, "set_filter_context", None)
            if callable(setter):
                setter(filters)

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
            except (sqlite3.Error, json.JSONDecodeError, UnicodeDecodeError, SQLCipherSupportError) as exc:
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
            max_threads=50,
        )
        return ExtractionResult(messages=limited_messages, stats=stats, grouped_threads=grouped_threads)

    def available_wechat_keys(self) -> list[dict[str, object]]:
        return [info.to_dict() for info in self._sqlcipher_helper.available_keys()]

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

        def latest_timestamp(items: list[Message]) -> datetime:
            best: datetime | None = None
            for msg in items:
                normalized = _normalize_datetime(msg.timestamp)
                if normalized and (best is None or normalized > best):
                    best = normalized
            return best or datetime.fromtimestamp(0, tz=DEFAULT_TIMEZONE)

        sorted_groups = sorted(
            grouped.items(),
            key=lambda item: (latest_timestamp(item[1]), len(item[1]), item[0].lower()),
            reverse=True,
        )
        produced: list[ConversationGroup] = []
        per_thread_limit = max(per_thread_limit, 1)
        max_threads = max(1, max_threads)
        for name, group_messages in sorted_groups[:max_threads]:
            ordered = sorted(
                group_messages,
                key=lambda msg: _normalize_datetime(msg.timestamp)
                or datetime.fromtimestamp(0, tz=DEFAULT_TIMEZONE),
            )
            trimmed = ordered[-per_thread_limit:]
            day_buckets: dict[str, list[Message]] = defaultdict(list)
            for message in trimmed:
                day_buckets[_message_day(message)].append(message)
            days = [
                ConversationDay(date=day, messages=sorted(bucket, key=_message_sort_key))
                for day, bucket in sorted(day_buckets.items())
            ]
            first_ts = _normalize_datetime(ordered[0].timestamp) if ordered else None
            last_ts = _normalize_datetime(ordered[-1].timestamp) if ordered else None
            produced.append(
                ConversationGroup(
                    name=name,
                    count=len(group_messages),
                    messages=trimmed,
                    first_timestamp=first_ts.isoformat() if first_ts else None,
                    last_timestamp=last_ts.isoformat() if last_ts else None,
                    days=days,
                )
            )
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


def _resolve_message_type(raw_type: object, sub_type: object | None = None) -> str:
    if raw_type is None:
        return "unknown"
    if isinstance(raw_type, str):
        stripped = raw_type.strip()
        if not stripped:
            return "unknown"
        if stripped.isdigit():
            return _resolve_message_type(int(stripped), sub_type)
        return _normalize_message_type(stripped)
    if isinstance(raw_type, (int, float)):
        value = int(raw_type)
        type_map = {
            1: "text",
            2: "text",
            3: "image",
            34: "voice",
            37: "friend_request",
            40: "contact_card",
            42: "name_card",
            43: "video",
            47: "sticker",
            48: "location",
            49: "app",
            50: "call",
            52: "voip_notify",
            53: "voip_invite",
            62: "short_video",
            10000: "system",
            10002: "recall",
            318767153: "file",
        }
        if value == 49:
            sub_value: int | None = None
            if isinstance(sub_type, (int, float)):
                sub_value = int(sub_type)
            elif isinstance(sub_type, str) and sub_type.strip().isdigit():
                sub_value = int(sub_type.strip())
            app_map = {
                3: "link",
                4: "music",
                5: "link",
                6: "file",
                7: "card",
                8: "product",
                10: "red_envelope",
                11: "transfer",
                14: "location_share",
                16: "mini_program",
                19: "voice_reminder",
                57: "calendar",
                63: "mini_program",
            }
            if sub_value is not None:
                return app_map.get(sub_value, "app")
        return type_map.get(value, f"type_{value}")
    return _normalize_message_type(raw_type)


def _normalize_message_type(raw: object) -> str:
    if raw is None:
        return "unknown"
    if isinstance(raw, str):
        value = raw.strip()
        if not value:
            return "unknown"
        if value.isdigit():
            return _resolve_message_type(int(value))
        normalized = value.lower()
        alias_map = {
            "text": "text",
            "txt": "text",
            "plain": "text",
            "image": "image",
            "img": "image",
            "picture": "image",
            "photo": "image",
            "voice": "voice",
            "audio": "voice",
            "video": "video",
            "short_video": "short_video",
            "file": "file",
            "document": "file",
            "app": "app",
            "link": "link",
            "sticker": "sticker",
            "emoji": "sticker",
            "location": "location",
            "system": "system",
            "recall": "recall",
        }
        return alias_map.get(normalized, normalized)
    if isinstance(raw, (int, float)):
        return _resolve_message_type(raw)
    return "unknown"


def _stringify_metadata_value(value: object) -> str:
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8", errors="ignore").strip()
            if decoded:
                return decoded
        except Exception:  # pragma: no cover - defensive
            pass
        return value.hex()
    return str(value)


def _derive_display_content(message_type: str, content: str, metadata: dict[str, str]) -> str:
    text = (content or "").strip()
    if text:
        return text
    placeholder = MESSAGE_TYPE_PLACEHOLDERS.get(message_type)
    candidates: list[str] = []
    for key in (
        "title",
        "fileName",
        "filename",
        "name",
        "description",
        "digest",
        "summary",
        "appmsgcontent",
        "link",
        "url",
    ):
        value = metadata.get(key)
        if value:
            candidates.append(value.strip())
    if not candidates and metadata.get("bytesExtra"):
        decoded = _decode_bytes_extra(metadata["bytesExtra"])
        if decoded:
            candidates.append(decoded)
    if candidates:
        return candidates[0]
    if placeholder:
        return placeholder
    return text or "[无内容]"


def _build_display_meta(
    message_type: str,
    content: str,
    metadata: Mapping[str, str],
    *,
    direction: str = "unknown",
) -> dict[str, object]:
    data = metadata or {}
    text = (content or "").strip()
    normalized_type = (message_type or "").lower()
    meta: dict[str, object] = {}

    def get_value(*keys: str) -> str:
        return _first_non_empty(*(data.get(key) for key in keys))

    def candidate_source(*keys: str, fallback: str = "", extensions: tuple[str, ...] | None = None) -> str:
        value = get_value(*keys)
        if not value and fallback:
            value = fallback
        if value and _is_placeholder(value):
            value = ""
        if not value:
            return ""
        if extensions and not _looks_like_path_with_extension(value, extensions):
            return ""
        return value

    if normalized_type in {"image", "sticker"}:
        url = candidate_source(
            "image_url",
            "imageUrl",
            "imagePath",
            "image",
            "mediaPath",
            "cdnurl",
            "cdn_url",
            "url",
            "dataurl",
            "thumbUrl",
            "thumb",
            fallback=text,
            extensions=(".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic"),
        )
        name = get_value("fileName", "filename", "name", "title") or _safe_basename(url or text)
        preview = get_value("thumb", "thumbnail", "preview", "cover", "coverUrl")
        meta = {"kind": "image"}
        if url:
            meta["url"] = url
        if preview and preview != url:
            meta["preview"] = preview
        if name:
            meta["name"] = name
        return meta

    if normalized_type in {"video", "short_video"}:
        url = candidate_source(
            "videoPath",
            "mediaPath",
            "cdnurl",
            "url",
            "dataurl",
            "filePath",
            fallback=text,
            extensions=(".mp4", ".mov", ".mkv", ".avi", ".flv", ".wmv", ".webm"),
        )
        name = get_value("fileName", "filename", "title", "name") or _safe_basename(url or text)
        duration_value = _parse_int(
            get_value("duration", "playLength", "length", "voiceLength", "videotime", "videotimeSecond")
        )
        preview = get_value("thumb", "thumbnail", "preview", "cover", "coverUrl")
        meta = {"kind": "video"}
        if url:
            meta["url"] = url
        if name:
            meta["name"] = name
        if duration_value:
            meta["duration"] = _format_duration(duration_value)
        if preview and preview != url:
            meta["preview"] = preview
        return meta

    if normalized_type in {"voice", "audio"}:
        url = candidate_source(
            "voicePath",
            "mediaPath",
            "cdnurl",
            "url",
            "dataurl",
            "filePath",
            fallback=text,
            extensions=(".mp3", ".aac", ".amr", ".wav", ".m4a", ".ogg"),
        )
        duration_value = _parse_int(
            get_value("duration", "playLength", "length", "voiceLength", "msgtime", "audiolength")
        )
        transcript = get_value("transcript", "text", "translate", "recognition")
        name = get_value("fileName", "filename", "name", "title") or _safe_basename(url or text)
        meta = {"kind": "audio"}
        if url:
            meta["url"] = url
        if duration_value:
            meta["duration"] = _format_duration(duration_value)
        if transcript:
            meta["transcript"] = transcript
        if name:
            meta["name"] = name
        return meta

    if normalized_type == "file":
        url = candidate_source(
            "filePath",
            "file_url",
            "url",
            "cdnurl",
            "mediaPath",
            "dataurl",
            fallback=text,
        )
        name = get_value("fileName", "filename", "name", "title") or _safe_basename(url or text)
        size_value = _parse_int(get_value("fileSize", "filesize", "size", "length"))
        extension = get_value("fileext", "ext", "extension") or (Path(name).suffix[1:] if name and Path(name).suffix else "")
        meta = {"kind": "file"}
        if url:
            meta["url"] = url
        if name:
            meta["name"] = name
        if size_value:
            meta["size"] = _format_file_size(size_value)
        if extension:
            meta["extension"] = extension.lower()
        return meta

    if normalized_type in {"link", "app", "rich_media"}:
        url = candidate_source(
            "url",
            "link",
            "appurl",
            "targetUrl",
            "appmsgcontent.url",
            fallback=text if _looks_like_url(text) else "",
        )
        title = get_value("title", "appmsgcontent.title", "name", "fileName")
        description = get_value("description", "digest", "summary", "appmsgcontent.des")
        cover = get_value("thumburl", "thumbnail", "cover", "coverUrl", "appmsgcontent.thumburl")
        meta = {"kind": "link"}
        if url:
            meta["url"] = url
        if title:
            meta["title"] = title
        if description:
            meta["description"] = description
        if cover:
            meta["cover"] = cover
        return meta

    if normalized_type in {"contact_card", "name_card"}:
        name = get_value("name", "nickname", "displayname", "alias", "title") or text
        wxid = get_value("wxid", "username", "userName", "userID", "userId")
        phone = get_value("phone", "mobile", "telephone", "tel")
        company = get_value("company", "corp", "organization", "org")
        meta = {"kind": "contact"}
        if name:
            meta["name"] = name
        if wxid:
            meta["account"] = wxid
        if phone:
            meta["phone"] = phone
        if company:
            meta["company"] = company
        return meta

    if normalized_type in {"call", "voip_notify", "voip_invite"}:
        status = get_value("status", "state", "callStatus", "remark", "description")
        duration_value = _parse_int(get_value("duration", "talktime", "time", "length"))
        meta = {"kind": "call"}
        if status:
            meta["status"] = status
        if duration_value:
            meta["duration"] = _format_duration(duration_value)
        if direction and direction != "unknown":
            meta["direction"] = direction
        note = get_value("note", "tips", "tip")
        if note:
            meta["note"] = note
        return meta

    return meta


def _extract_metadata_fields(payload: Mapping[str, object]) -> dict[str, str]:
    if not isinstance(payload, Mapping):
        return {}
    ignore_keys = {
        "talker",
        "sender",
        "timestamp",
        "message_type",
        "type",
        "content",
        "msgid",
        "msgId",
    }
    collected: dict[str, str] = {}
    for key, value in payload.items():
        if key in ignore_keys or value is None:
            continue
        if len(collected) >= 25:
            break
        if isinstance(value, (str, int, float, bool)):
            text = _stringify_metadata_value(value).strip()
            if text:
                collected[key] = text
            continue
        if isinstance(value, Mapping):
            for sub_key, sub_value in value.items():
                if len(collected) >= 25:
                    break
                if isinstance(sub_value, (str, int, float, bool)) and sub_value is not None:
                    text = _stringify_metadata_value(sub_value).strip()
                    if text:
                        collected[f"{key}.{sub_key}"] = text
            continue
        if isinstance(value, (list, tuple, set)):
            items: list[str] = []
            for item in list(value)[:5]:
                if isinstance(item, (str, int, float, bool)):
                    text = _stringify_metadata_value(item).strip()
                    if text:
                        items.append(text)
            if items:
                collected[key] = ", ".join(items)
            continue
    return collected


def _first_non_empty(*values: object) -> str:
    for value in values:
        if value is None:
            continue
        text = _stringify_metadata_value(value).strip()
        if text:
            return text
    return ""


def _is_placeholder(value: str) -> bool:
    return value in MESSAGE_TYPE_PLACEHOLDERS.values()


def _looks_like_url(value: str) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc)


def _looks_like_path_with_extension(value: str, extensions: tuple[str, ...] | None = None) -> bool:
    if not value:
        return False
    lower = value.lower()
    if lower.startswith("http://") or lower.startswith("https://") or lower.startswith("file://") or lower.startswith("data:"):
        if extensions:
            return any(lower.endswith(ext) for ext in extensions)
        return True
    if extensions:
        return any(lower.endswith(ext) for ext in extensions)
    return "/" in value or "\\" in value or "." in Path(value).suffix


def _safe_basename(value: str) -> str:
    if not value:
        return ""
    candidate = value.split("?")[0].split("#")[0]
    try:
        name = Path(candidate).name
    except Exception:  # pragma: no cover - defensive
        name = candidate.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name or candidate


def _parse_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(float(str(value).strip()))
    except (ValueError, TypeError):
        return None


def _format_file_size(value: int) -> str:
    if value < 0:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024
    return f"{value} B"


def _format_duration(total_seconds: int) -> str:
    total_seconds = max(total_seconds, 0)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:d}:{seconds:02d}"


def _decode_bytes_extra(raw: str) -> str | None:
    data = raw.strip()
    if not data:
        return None
    lower = data.lower()
    if lower.startswith("{") and lower.endswith("}"):
        try:
            parsed = json.loads(data)
            if isinstance(parsed, dict):
                for key in ("title", "description", "url", "fileName"):
                    if key in parsed and parsed[key]:
                        return str(parsed[key]).strip()
                return json.dumps(parsed, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    if lower.startswith("<") and lower.endswith(">"):
        try:
            element = ET.fromstring(data)
        except ET.ParseError:
            return None
        texts = [element.text.strip() for element in element.iter() if element.text and element.text.strip()]
        return texts[0] if texts else None
    return data[:200]


def _message_day(message: Message) -> str:
    normalized = _normalize_datetime(message.timestamp)
    if normalized:
        return normalized.date().isoformat()
    return "未知日期"
