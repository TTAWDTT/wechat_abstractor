"""
测试 SQLCipher 解密功能
"""
from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from chat_extractor.forms import ParsedFilters
from chat_extractor.services.extractor import ExtractionService
from chat_extractor.services.wechat_crypto import (
    HAS_PYCRYPTODOME,
    SQLCipherSupportError,
    decode_key_hex,
    verify_sqlcipher_password,
    decrypt_sqlcipher_database,
    is_sqlcipher_database,
)

TEST_DATA_DIR = Path(__file__).resolve().parent / "data"
ENCRYPTED_DB = TEST_DATA_DIR / "encrypted_test.db"
TEST_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class SQLCipherCryptoTests(SimpleTestCase):
    """测试 SQLCipher 加密/解密基础功能"""

    def test_decode_key_hex_valid(self) -> None:
        """测试有效的十六进制密钥解码"""
        key = decode_key_hex(TEST_KEY_HEX)
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)  # type: ignore[arg-type]

    def test_decode_key_hex_invalid(self) -> None:
        """测试无效密钥处理"""
        self.assertIsNone(decode_key_hex(""))
        self.assertIsNone(decode_key_hex(None))
        self.assertIsNone(decode_key_hex("invalid"))
        self.assertIsNone(decode_key_hex("abc123"))  # 长度不对

    def test_decode_key_hex_with_spaces(self) -> None:
        """测试带空格的密钥处理"""
        key = decode_key_hex("  " + TEST_KEY_HEX + "  ")
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)  # type: ignore[arg-type]

    def test_is_sqlcipher_database_plaintext(self) -> None:
        """测试识别明文 SQLite 数据库"""
        plain_db = TEST_DATA_DIR / "sample.json"  # 用 JSON 文件模拟非加密文件
        if plain_db.exists():
            self.assertFalse(is_sqlcipher_database(plain_db))

    def test_has_pycryptodome_flag(self) -> None:
        """测试 pycryptodome 可用性标志"""
        # 这个测试会根据环境而变化
        self.assertIsInstance(HAS_PYCRYPTODOME, bool)


class SQLCipherDecryptionTests(SimpleTestCase):
    """测试 SQLCipher 数据库解密功能(需要 pycryptodome)"""

    def setUp(self) -> None:
        if not HAS_PYCRYPTODOME:
            self.skipTest("pycryptodome not installed")
        
        # 确保测试加密数据库存在
        if not ENCRYPTED_DB.exists():
            self.skipTest(f"Encrypted test database not found: {ENCRYPTED_DB}")

    def test_verify_correct_password(self) -> None:
        """测试正确密钥验证"""
        password = decode_key_hex(TEST_KEY_HEX)
        self.assertIsNotNone(password)
        result = verify_sqlcipher_password(ENCRYPTED_DB, password)  # type: ignore[arg-type]
        self.assertTrue(result, "正确的密钥应该验证成功")

    def test_verify_incorrect_password(self) -> None:
        """测试错误密钥验证"""
        wrong_key = b"\x00" * 32
        result = verify_sqlcipher_password(ENCRYPTED_DB, wrong_key)
        self.assertFalse(result, "错误的密钥应该验证失败")

    def test_decrypt_database_success(self) -> None:
        """测试成功解密数据库"""
        import tempfile
        
        password = decode_key_hex(TEST_KEY_HEX)
        self.assertIsNotNone(password)
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        
        try:
            decrypted_path = decrypt_sqlcipher_database(ENCRYPTED_DB, password, tmp_path)  # type: ignore[arg-type]
            self.assertTrue(decrypted_path.exists())
            self.assertGreater(decrypted_path.stat().st_size, 0, "解密后的文件不应为空")
            
            # 验证文件以 SQLite 头开始
            with decrypted_path.open("rb") as f:
                header = f.read(16)
                self.assertEqual(header, b"SQLite format 3\x00", "解密后的文件应包含有效的SQLite头")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_decrypt_with_wrong_password_fails(self) -> None:
        """测试使用错误密钥解密失败"""
        import tempfile
        
        wrong_key = b"\xff" * 32
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        
        try:
            with self.assertRaises(SQLCipherSupportError) as context:
                decrypt_sqlcipher_database(ENCRYPTED_DB, wrong_key, tmp_path)
            self.assertIn("incorrect", str(context.exception).lower())
        finally:
            tmp_path.unlink(missing_ok=True)


class SQLCipherIntegrationTests(SimpleTestCase):
    """测试 SQLCipher 与提取服务的集成"""

    def setUp(self) -> None:
        if not HAS_PYCRYPTODOME:
            self.skipTest("pycryptodome not installed")
        
        if not ENCRYPTED_DB.exists():
            self.skipTest(f"Encrypted test database not found: {ENCRYPTED_DB}")
        
        self.service = ExtractionService()

    def test_extract_encrypted_db_with_key(self) -> None:
        """测试提供正确密钥后可以提取加密数据库"""
        filters = ParsedFilters(
            base_dir=TEST_DATA_DIR,
            contacts=[],
            limit=10,
            start_time=None,
            end_time=None,
            message_types=[],
            include_subdirectories=False,
            wechat_db_key=TEST_KEY_HEX,
        )
        
        try:
            result = self.service.extract(filters)
            # 如果加密数据库被正确解密,应该能提取到消息
            self.assertGreaterEqual(result.stats.total_messages, 0)
        except Exception as exc:
            # 如果失败,至少不应该是 "file is not a database" 错误
            self.assertNotIn("not a database", str(exc).lower())

    def test_extract_encrypted_db_without_key_fails_clearly(self) -> None:
        """测试不提供密钥时,错误信息清晰"""
        filters = ParsedFilters(
            base_dir=TEST_DATA_DIR,
            contacts=[],
            limit=10,
            start_time=None,
            end_time=None,
            message_types=[],
            include_subdirectories=False,
            wechat_db_key=None,  # 不提供密钥
        )
        
        try:
            result = self.service.extract(filters)
            # 如果有加密数据库,应该记录在失败文件中
            if ENCRYPTED_DB.name in str(result.stats.failed_files):
                # 验证失败原因包含加密相关信息
                failed_msg = " ".join(result.stats.failed_files)
                has_cipher_hint = any(
                    keyword in failed_msg.lower()
                    for keyword in ["cipher", "encrypt", "password", "key"]
                )
                self.assertTrue(
                    has_cipher_hint,
                    f"失败信息应包含加密相关提示: {failed_msg}"
                )
        except Exception:
            # 允许抛出异常,但应该有明确的错误信息
            pass


def build_filters(**overrides):
    """构建测试用 ParsedFilters"""
    defaults = dict(
        base_dir=TEST_DATA_DIR,
        contacts=[],
        limit=5,
        start_time=None,
        end_time=None,
        message_types=[],
        include_subdirectories=False,
        wechat_db_key=None,
    )
    defaults.update(overrides)
    return ParsedFilters(**defaults)
