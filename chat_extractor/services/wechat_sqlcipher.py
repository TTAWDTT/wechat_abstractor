from __future__ import annotations

import hashlib
import logging
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from ..forms import ParsedFilters
from .wechat_crypto import (
    SQLCipherSupportError,
    decode_key_hex,
    decrypt_sqlcipher_database,
    ensure_sqlite_header,
    is_sqlcipher_database,
    verify_sqlcipher_password,
)
from .wechat_process import WeChatKeyInfo, discover_wechat_keys

LOGGER = logging.getLogger(__name__)


class WeChatSQLCipherHelper:
    def __init__(self) -> None:
        self._manual_key: bytes | None = None
        self._cache: Dict[tuple[str, str], Path] = {}
        self._cache_root = Path(tempfile.gettempdir()) / "wechat_abstractor" / "decrypted_db"
        self._cache_root.mkdir(parents=True, exist_ok=True)
        self._cached_keys: Tuple[float, List[WeChatKeyInfo]] | None = None

    def set_manual_key(self, key_hex: str | None) -> None:
        self._manual_key = decode_key_hex(key_hex)

    def open_connection(self, path: Path, filters: ParsedFilters | None) -> sqlite3.Connection:
        base_error: Exception | None = None
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.DatabaseError as exc:
            base_error = exc
        else:
            try:
                connection.execute("PRAGMA schema_version;")
            except sqlite3.DatabaseError as exc:
                connection.close()
                base_error = exc
            else:
                return connection

        if not is_sqlcipher_database(path):
            if base_error:
                raise base_error
            raise SQLCipherSupportError("failed to open database")

        keys = list(self._iter_candidate_keys(path, filters))
        last_error: Exception | None = base_error
        for key in keys:
            try:
                decrypted_path = self._get_or_create_plaintext(path, key)
            except SQLCipherSupportError as crypto_error:
                last_error = crypto_error
                continue
            try:
                connection = sqlite3.connect(f"file:{decrypted_path}?mode=ro", uri=True)
            except sqlite3.DatabaseError as inner_exc:
                last_error = inner_exc
                continue
            try:
                connection.execute("PRAGMA schema_version;")
            except sqlite3.DatabaseError as inner_exc:
                connection.close()
                last_error = inner_exc
                continue
            return connection

        # 所有密钥尝试都失败
        if last_error:
            raise last_error
        raise SQLCipherSupportError("no valid SQLCipher key candidates succeeded")

    def available_keys(self) -> List[WeChatKeyInfo]:
        return list(self._system_keys())

    def _iter_candidate_keys(self, path: Path, filters: ParsedFilters | None) -> Iterable[bytes]:
        seen: set[str] = set()

        if self._manual_key:
            hex_key = self._manual_key.hex()
            seen.add(hex_key)
            yield self._manual_key

        if filters and filters.wechat_db_key:
            manual = decode_key_hex(filters.wechat_db_key)
            if manual:
                hex_key = manual.hex()
                if hex_key not in seen:
                    seen.add(hex_key)
                    yield manual

        if not filters:
            return

        base_dir = filters.base_dir.resolve()
        for info in self._system_keys():
            if not info.key_hex:
                continue
            key_bytes = decode_key_hex(info.key_hex)
            if not key_bytes:
                continue
            base_path = info.base_path.resolve()
            if _is_relative_to(path, base_path) or _is_relative_to(base_dir, base_path):
                hex_key = key_bytes.hex()
                if hex_key not in seen:
                    seen.add(hex_key)
                    yield key_bytes

    def _get_or_create_plaintext(self, source: Path, key: bytes) -> Path:
        cache_key = (str(source.resolve()), key.hex())
        if cache_key in self._cache:
            cached_path = self._cache[cache_key]
            if cached_path.exists() and ensure_sqlite_header(cached_path):
                return cached_path

        digest = hashlib.sha1((source.as_posix() + key.hex()).encode("utf-8")).hexdigest()
        target = self._cache_root / f"{digest}_{source.name}"

        if not verify_sqlcipher_password(source, key):
            raise SQLCipherSupportError("provided SQLCipher key did not match the database")

        decrypted_path = decrypt_sqlcipher_database(source, key, target)
        if not ensure_sqlite_header(decrypted_path):
            raise SQLCipherSupportError("decrypted output missing SQLite header")

        self._cache[cache_key] = decrypted_path
        return decrypted_path

    def _system_keys(self) -> List[WeChatKeyInfo]:
        now = time.monotonic()
        if self._cached_keys and now - self._cached_keys[0] < 5:
            return self._cached_keys[1]
        keys = discover_wechat_keys()
        if keys:
            LOGGER.info("Discovered %d WeChat process key(s)", len(keys))
        self._cached_keys = (now, keys)
        return keys


def _is_relative_to(path: Path, other: Path) -> bool:
    try:
        path.relative_to(other)
        return True
    except ValueError:
        return False
