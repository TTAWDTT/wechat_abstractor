"""
SQLCipher 测试数据库生成脚本

使用 pycryptodome 创建加密的 SQLite 数据库用于测试
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import tempfile
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("需要安装 pycryptodome: pip install pycryptodome")
    exit(1)

DEFAULT_ITERATIONS = 64000
KEY_SIZE = 32
DEFAULT_PAGE_SIZE = 4096


def pbkdf2_hmac_sha1(password: bytes, salt: bytes, iterations: int, key_len: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, salt, iterations, key_len)


def create_encrypted_test_db(output_path: Path, password: bytes) -> None:
    """创建一个加密的 SQLite 数据库用于测试"""
    
    # 1. 先创建一个普通的 SQLite 数据库
    temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_db.close()
    temp_path = Path(temp_db.name)
    
    try:
        # 创建测试数据
        conn = sqlite3.connect(str(temp_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE MSG (
                localId INTEGER PRIMARY KEY,
                StrTalker TEXT,
                CreateTime INTEGER,
                Type INTEGER,
                SubType INTEGER,
                IsSender INTEGER,
                StrContent TEXT,
                BytesExtra BLOB
            )
        """)
        
        cursor.execute("""
            INSERT INTO MSG (StrTalker, CreateTime, Type, SubType, IsSender, StrContent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("test_user", 1609459200, 1, 0, 0, "这是一条加密测试消息"))
        
        cursor.execute("""
            INSERT INTO MSG (StrTalker, CreateTime, Type, SubType, IsSender, StrContent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("test_user", 1609459260, 1, 0, 1, "这是回复消息"))
        
        conn.commit()
        conn.close()
        
        # 2. 读取普通数据库内容
        with temp_path.open("rb") as f:
            plaintext_data = f.read()
        
        # 3. 使用 SQLCipher 格式加密
        # 生成随机 salt
        import os
        salt = os.urandom(16)
        
        # 派生密钥
        key = pbkdf2_hmac_sha1(password, salt, DEFAULT_ITERATIONS, KEY_SIZE)
        mac_salt = bytes(byte ^ 0x3A for byte in salt)
        mac_key = pbkdf2_hmac_sha1(key, mac_salt, 2, KEY_SIZE)
        
        # 准备输出文件
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with output_path.open("wb") as out:
            # 处理第一页
            # 加密前第一页: SQLite header(16) + data(4048-48) + reserved_for_trailer(48) = 4096字节
            # 加密后第一页: Salt(16) + encrypted(4032) + IV(16) + HMAC(20) + reserved(12) = 4096字节
            
            page1_data = plaintext_data[:DEFAULT_PAGE_SIZE]
            if len(page1_data) < DEFAULT_PAGE_SIZE:
                page1_data = page1_data + b"\x00" * (DEFAULT_PAGE_SIZE - len(page1_data))
            
            # 加密内容: 跳过SQLite头(前16字节),加密到倒数48字节
            # 即加密 page1_data[16:4048] = 4032字节
            page1_to_encrypt = page1_data[16:DEFAULT_PAGE_SIZE-48]
            
            # 生成第一页IV
            iv1_source = salt + b"\x01\x00\x00\x00"
            iv1 = hashlib.sha256(iv1_source).digest()[:16]
            
            # 加密
            cipher = AES.new(key, AES.MODE_CBC, iv1)
            encrypted_page1 = cipher.encrypt(page1_to_encrypt)
            
            # 计算HMAC (对4080字节的page1数据,即除Salt外的所有内容)
            # HMAC输入: encrypted(4032) + IV(16) 共4048字节,即除了HMAC(20)+reserved(12)=32字节
            mac = hmac.new(mac_key, digestmod="sha1")
            mac.update(encrypted_page1)  # 4032字节加密内容
            mac.update(iv1)              # 16字节IV
            mac.update(b"\x01\x00\x00\x00")  # 页号1,小端序
            page1_hmac = mac.digest()
            
            # 写入第一页: Salt(16) + encrypted(4032) + IV(16) + HMAC(20) + reserved(12) = 4096
            out.write(salt)
            out.write(encrypted_page1)
            out.write(iv1)
            out.write(page1_hmac)
            out.write(b"\x00" * 12)
            
            # 处理后续页面
            offset = DEFAULT_PAGE_SIZE
            page_num = 2
            
            while offset < len(plaintext_data):
                page_data = plaintext_data[offset:offset + DEFAULT_PAGE_SIZE]
                
                # 如果不足一页,填充零
                if len(page_data) < DEFAULT_PAGE_SIZE:
                    page_data = page_data + b"\x00" * (DEFAULT_PAGE_SIZE - len(page_data))
                
                # 生成 IV
                iv_source = salt + page_num.to_bytes(4, "big")
                iv = hashlib.sha256(iv_source).digest()[:16]
                
                # 加密页面内容 (保留最后48字节)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_content = cipher.encrypt(page_data[:-48])
                
                # 计算 HMAC
                mac = hmac.new(mac_key, digestmod="sha1")
                mac.update(encrypted_content)
                mac.update(iv)
                mac.update(page_num.to_bytes(4, "little"))
                page_hmac = mac.digest()
                
                # 写入: 加密内容 + IV + HMAC + 保留
                out.write(encrypted_content)
                out.write(iv)
                out.write(page_hmac)
                out.write(b"\x00" * 12)
                
                offset += DEFAULT_PAGE_SIZE
                page_num += 1
        
        print(f"✓ 创建加密数据库: {output_path}")
        print(f"  密钥: {password.hex()}")
        print(f"  Salt: {salt.hex()}")
        
    finally:
        # 清理临时文件
        temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    # 生成测试密钥
    test_key = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    
    # 创建测试数据库
    test_data_dir = Path(__file__).parent / "data"
    encrypted_db_path = test_data_dir / "encrypted_test.db"
    
    create_encrypted_test_db(encrypted_db_path, test_key)
    
    print("\n使用方法:")
    print("1. 在测试或前端中输入密钥: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    print("2. 指定数据库路径进行解密测试")
