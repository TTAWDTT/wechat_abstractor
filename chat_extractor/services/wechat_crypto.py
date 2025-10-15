from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import BinaryIO

try:  # PyCryptodome provides the AES primitive we need.
    from Crypto.Cipher import AES  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - handled at runtime when encryption features are used.
    AES = None  # type: ignore[assignment]

HAS_PYCRYPTODOME = AES is not None

LOGGER = logging.getLogger(__name__)

SQLITE_HEADER = b"SQLite format 3\x00"
DEFAULT_ITERATIONS = 64000
KEY_SIZE = 32
DEFAULT_PAGE_SIZE = 4096


class SQLCipherSupportError(RuntimeError):
    """Raised when SQLCipher-specific handling cannot proceed."""


def _ensure_aes_available() -> None:
    if AES is None:  # pragma: no cover - only hit when dependency missing.
        raise SQLCipherSupportError(
            "pycryptodome is required for SQLCipher database decryption. Install it via 'pip install pycryptodome'."
        )


def _derive_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, salt, DEFAULT_ITERATIONS, KEY_SIZE)


def _derive_hmac_key(key: bytes, salt: bytes, iterations: int = 2) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", key, salt, iterations, KEY_SIZE)


def _compute_page_hmac(page: bytes, mac_key: bytes, page_num: int = 1) -> bytes:
    """计算 SQLCipher 页面 HMAC
    
    Args:
        page: 完整页面数据(包含加密内容和trailer)
        mac_key: HMAC密钥
        page_num: 页号(从1开始)
    """
    mac = hmac.new(mac_key, digestmod="sha1")
    mac.update(page[:-32])  # 除了最后32字节(HMAC+保留)
    mac.update(page_num.to_bytes(4, "little"))
    return mac.digest()


def _read_first_page(handle: BinaryIO) -> bytes:
    data = handle.read(DEFAULT_PAGE_SIZE)
    if len(data) != DEFAULT_PAGE_SIZE:
        raise SQLCipherSupportError("failed to read the first database page")
    return data


def is_sqlcipher_database(path: Path) -> bool:
    """
    判断文件是否为 SQLCipher 加密数据库
    
    逻辑:
    - 文件头是 'SQLite format 3' → 明文数据库 (False)
    - 文件大小 >= 1024 且文件头不是 SQLite → 可能是 SQLCipher (True)
    - 其他情况 → 无效或损坏文件 (False)
    """
    try:
        file_size = path.stat().st_size
        if file_size < DEFAULT_PAGE_SIZE:
            return False
        
        with path.open("rb") as handle:
            header = handle.read(len(SQLITE_HEADER))
            
        # 明文 SQLite 数据库
        if header == SQLITE_HEADER:
            return False
            
        # 文件大小足够且不是明文 SQLite,疑似 SQLCipher
        return True
        
    except OSError:
        return False


def decode_key_hex(value: str | None) -> bytes | None:
    if not value:
        return None
    raw = value.strip().lower()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        LOGGER.warning("Failed to decode provided SQLCipher key", exc_info=True)
        return None
    if len(key) != KEY_SIZE:
        LOGGER.warning("Provided SQLCipher key has length %d, expected %d", len(key), KEY_SIZE)
        return None
    return key


def verify_sqlcipher_password(path: Path, password: bytes) -> bool:
    """验证 SQLCipher 密钥是否正确
    
    通过校验第一页的 HMAC 来判断密钥正确性
    """
    try:
        with path.open("rb") as handle:
            first_page = _read_first_page(handle)
    except (OSError, SQLCipherSupportError):
        return False

    salt = first_page[:16]
    key = _derive_key(password, salt)
    page = first_page[16:]  # Salt之后的所有内容

    mac_salt = bytes(byte ^ 0x3A for byte in salt)
    mac_key = _derive_hmac_key(key, mac_salt)
    computed = _compute_page_hmac(page, mac_key, page_num=1)
    stored = page[-32:-12]  # HMAC(20字节)存储位置
    return hmac.compare_digest(computed, stored)


def decrypt_sqlcipher_database(source: Path, password: bytes, destination: Path) -> Path:
    """解密 SQLCipher 数据库
    
    Args:
        source: 加密数据库路径
        password: 32字节密钥
        destination: 解密后输出路径
    
    Returns:
        解密后的数据库路径
    """
    if not source.exists():
        raise SQLCipherSupportError(f"database does not exist: {source}")
    _ensure_aes_available()

    with source.open("rb") as handle:
        first_page = _read_first_page(handle)

        salt = first_page[:16]
        key = _derive_key(password, salt)
        page = first_page[16:]  # Salt之后的内容

        mac_salt = bytes(byte ^ 0x3A for byte in salt)
        mac_key = _derive_hmac_key(key, mac_salt)
        
        # 验证第一页的HMAC
        computed = _compute_page_hmac(page, mac_key, page_num=1)
        stored = page[-32:-12]
        if not hmac.compare_digest(computed, stored):
            raise SQLCipherSupportError("incorrect SQLCipher password")

        # 解密第一页
        iv = page[-48:-32]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(page[:-48])  # 解密4032字节
        trailer = page[-48:]

        tmp_path = destination
        tmp_path.parent.mkdir(parents=True, exist_ok=True)
        with tmp_path.open("wb") as out:
            # 第一页: 手动写入SQLite头(16字节) + 解密内容(4032字节) + trailer(48字节) = 4096
            out.write(SQLITE_HEADER)
            out.write(decrypted)
            out.write(trailer)

            # 处理后续页面
            page_num = 2
            while True:
                chunk = handle.read(DEFAULT_PAGE_SIZE)
                if not chunk:
                    break
                if len(chunk) != DEFAULT_PAGE_SIZE:
                    raise SQLCipherSupportError("unexpected page length during decryption")
                
                iv = chunk[-48:-32]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_chunk = cipher.decrypt(chunk[:-48])
                out.write(decrypted_chunk)
                out.write(chunk[-48:])
                page_num += 1

    return tmp_path


def ensure_sqlite_header(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(len(SQLITE_HEADER))
    except OSError:
        return False
    return header == SQLITE_HEADER
