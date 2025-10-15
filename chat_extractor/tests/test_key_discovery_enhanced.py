"""Enhanced tests for WeChat key discovery improvements.

This test suite validates the enhancements made to match wechatDataBackup Go implementation:
1. Version extraction from WeChatWin.dll
2. Improved logging and debug output
3. Precise boundary checks in key pointer search
4. Multiple device symbol support (android/pad-android/iphone/ipad/OHOS)
"""

import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# Configure detailed logging for tests
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stdout
)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from chat_extractor.services import wechat_process


class TestDeviceSymbolDetection:
    """Test device symbol detection (android/pad-android/iphone/ipad/OHOS)."""
    
    def test_android_symbol(self):
        """Test detection of 'android' device symbol."""
        # android + 9 null bytes + 0x07 + 3 null bytes
        buffer = b"\x00" * 100 + b"android" + b"\x00" * 9 + b"\x07\x00\x00\x00" + b"\x00" * 50
        result = wechat_process._find_device_symbol(buffer)
        assert result == 100, "Should find android symbol at offset 100"
    
    def test_pad_android_symbol(self):
        """Test detection of 'pad-android' device symbol."""
        # pad-android + 7 null bytes + 0x0B + 3 null bytes
        buffer = b"\x00" * 50 + b"pad-android" + b"\x00" * 7 + b"\x0B\x00\x00\x00"
        result = wechat_process._find_device_symbol(buffer)
        assert result == 50, "Should find pad-android symbol at offset 50"
    
    def test_iphone_symbol(self):
        """Test detection of 'iphone' device symbol."""
        # iphone + 10 null bytes + 0x06 + 3 null bytes
        buffer = b"iphone" + b"\x00" * 10 + b"\x06\x00\x00\x00" + b"\x00" * 100
        result = wechat_process._find_device_symbol(buffer)
        assert result == 0, "Should find iphone symbol at offset 0"
    
    def test_ipad_symbol(self):
        """Test detection of 'ipad' device symbol."""
        # ipad + 12 null bytes + 0x04 + 3 null bytes
        buffer = b"\xFF" * 200 + b"ipad" + b"\x00" * 12 + b"\x04\x00\x00\x00"
        result = wechat_process._find_device_symbol(buffer)
        assert result == 200, "Should find ipad symbol at offset 200"
    
    def test_ohos_symbol(self):
        """Test detection of 'OHOS' device symbol."""
        # OHOS + 12 null bytes + 0x04 + 3 null bytes
        buffer = b"OHOS" + b"\x00" * 12 + b"\x04\x00\x00\x00" + b"data"
        result = wechat_process._find_device_symbol(buffer)
        assert result == 0, "Should find OHOS symbol at offset 0"
    
    def test_no_symbol(self):
        """Test that -1 is returned when no symbol is found."""
        buffer = b"\x00" * 1000 + b"random data" + b"\xFF" * 500
        result = wechat_process._find_device_symbol(buffer)
        assert result == -1, "Should return -1 when no device symbol found"
    
    def test_symbol_priority(self):
        """Test that first matching symbol is returned."""
        # Place ipad before android
        buffer = b"ipad" + b"\x00" * 12 + b"\x04\x00\x00\x00" + b"\x00" * 50 + b"android" + b"\x00" * 9 + b"\x07\x00\x00\x00"
        result = wechat_process._find_device_symbol(buffer)
        assert result == 0, "Should find first symbol (ipad) at offset 0"


class TestKeyPointerCandidates:
    """Test key pointer candidate search improvements."""
    
    def test_32bit_key_pointer_search(self):
        """Test key pointer search in 32-bit process memory."""
        # Create buffer with pointer (0x12345678) followed by length marker (0x20)
        buffer = b"\x00" * 100
        buffer += b"\x78\x56\x34\x12"  # Little-endian pointer
        buffer += b"\x20\x00\x00\x00"  # Length marker: 32 bytes
        buffer += b"\x00" * 50
        
        candidates = wechat_process._find_key_pointer_candidates(buffer, is_64bit=False)
        assert len(candidates) > 0, "Should find at least one candidate"
        assert 0x12345678 in candidates, "Should find pointer 0x12345678"
    
    def test_64bit_key_pointer_search(self):
        """Test key pointer search in 64-bit process memory."""
        # Create buffer with 64-bit pointer followed by length marker
        buffer = b"\x00" * 200
        buffer += b"\xEF\xBE\xAD\xDE\x00\x00\x00\x00"  # 64-bit pointer
        buffer += b"\x20\x00\x00\x00\x00\x00\x00\x00"  # 64-bit length marker
        buffer += b"\x00" * 100
        
        candidates = wechat_process._find_key_pointer_candidates(buffer, is_64bit=True)
        assert len(candidates) > 0, "Should find at least one candidate"
        assert 0xDEADBEEF in candidates, "Should find pointer 0xDEADBEEF"
    
    def test_boundary_check_beginning(self):
        """Test that search handles beginning of buffer correctly (offset >= step)."""
        # Place key pointer very early in buffer
        buffer = b"\x00\x00\x00\x00"  # 4 bytes padding
        buffer += b"\xFF\xFF\x00\x00"  # Pointer
        buffer += b"\x20\x00\x00\x00"  # Length marker
        buffer += b"\x00" * 50
        
        candidates = wechat_process._find_key_pointer_candidates(buffer, is_64bit=False)
        # Should find the pointer at offset 4
        assert 0x0000FFFF in candidates, "Should find pointer even at beginning of buffer"
    
    def test_multiple_candidates(self):
        """Test finding multiple key pointer candidates."""
        buffer = b""
        # Add 3 candidates
        for i in range(3):
            buffer += b"\x00" * 20
            buffer += (0x1000 + i * 0x100).to_bytes(4, "little")
            buffer += b"\x20\x00\x00\x00"
        buffer += b"\x00" * 50
        
        candidates = wechat_process._find_key_pointer_candidates(buffer, is_64bit=False)
        assert len(candidates) >= 3, f"Should find at least 3 candidates, found {len(candidates)}"
    
    def test_empty_buffer(self):
        """Test that empty buffer returns no candidates."""
        candidates = wechat_process._find_key_pointer_candidates(b"", is_64bit=False)
        assert len(candidates) == 0, "Empty buffer should yield no candidates"
    
    def test_null_pointer_included(self):
        """Test that null pointers are still included (filtered in _probe_keys)."""
        buffer = b"\x00" * 20
        buffer += b"\x00\x00\x00\x00"  # Null pointer
        buffer += b"\x20\x00\x00\x00"  # Length marker
        buffer += b"\x00" * 50
        
        candidates = wechat_process._find_key_pointer_candidates(buffer, is_64bit=False)
        assert 0 in candidates, "Null pointer should be included in candidates"


class TestVersionExtraction:
    """Test DLL version extraction functionality."""
    
    @patch('ctypes.windll.version.GetFileVersionInfoSizeW')
    @patch('ctypes.windll.version.GetFileVersionInfoW')
    @patch('ctypes.windll.version.VerQueryValueW')
    def test_version_extraction_success(self, mock_query, mock_info, mock_size):
        """Test successful version extraction."""
        import ctypes
        
        mock_size.return_value = 1024  # Size of version info
        mock_info.return_value = True
        
        # Mock VS_FIXEDFILEINFO structure - must persist beyond side_effect function
        # Version 3.9.8.25 = 0x00030009.00080019
        file_info = (ctypes.c_uint32 * 13)()
        file_info[2] = 0x00030009  # dwFileVersionMS: major.minor
        file_info[3] = 0x00080019  # dwFileVersionLS: build.revision
        
        def query_side_effect(buffer, query, value_ptr, size_ptr):
            # Set the pointer to our structure
            ctypes.cast(value_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(file_info)
            ctypes.cast(size_ptr, ctypes.POINTER(ctypes.c_uint))[0] = 52  # Size of VS_FIXEDFILEINFO
            return True
        
        mock_query.side_effect = query_side_effect
        
        version = wechat_process._extract_dll_version("C:\\Test\\WeChatWin.dll")
        assert version == "3.9.8.25", f"Expected version 3.9.8.25, got {version}"
    
    @patch('ctypes.windll.version.GetFileVersionInfoSizeW')
    def test_version_extraction_no_version_info(self, mock_size):
        """Test handling when DLL has no version info."""
        mock_size.return_value = 0  # No version info available
        
        version = wechat_process._extract_dll_version("C:\\Test\\NoVersion.dll")
        assert version == "", "Should return empty string when no version info"
    
    @patch('ctypes.windll.version.GetFileVersionInfoSizeW')
    def test_version_extraction_exception(self, mock_size):
        """Test handling of exceptions during version extraction."""
        mock_size.side_effect = Exception("Access denied")
        
        version = wechat_process._extract_dll_version("C:\\Test\\Protected.dll")
        assert version == "", "Should return empty string on exception"


class TestLoggingEnhancements:
    """Test that enhanced logging works correctly."""
    
    def test_discover_logs_summary(self, caplog):
        """Test that discover_wechat_keys logs summary information."""
        caplog.set_level(logging.INFO)
        
        with patch('psutil.process_iter', return_value=[]):
            wechat_process.discover_wechat_keys()
        
        # Check for key log messages
        assert "Starting WeChat key discovery" in caplog.text
        assert "Key discovery complete" in caplog.text
    
    def test_extract_key_logs_details(self, caplog):
        """Test that _extract_key_hex logs detailed progress."""
        caplog.set_level(logging.DEBUG)
        
        # Create mock context
        context = wechat_process._ProcessContext(
            pid=1234,
            base_path=Path("C:\\Users\\Test\\WeChat"),
            media_db=Path("C:\\Users\\Test\\WeChat\\Msg\\Media.db"),
            account="TestAccount",
            dll_base=0x10000000,
            dll_size=1024,
            is_64bit=True,
            dll_version="3.9.8.25"
        )
        
        with patch('ctypes.windll.kernel32.OpenProcess', return_value=0):
            result = wechat_process._extract_key_hex(context)
        
        assert result is None
        assert "Starting key extraction" in caplog.text
        assert "PID: 1234" in caplog.text
        assert "Version: 3.9.8.25" in caplog.text


class TestIntegrationScenarios:
    """Integration tests for complete key discovery workflow."""
    
    def test_no_wechat_running(self):
        """Test behavior when WeChat is not running."""
        with patch('psutil.process_iter', return_value=[]):
            results = wechat_process.discover_wechat_keys()
            assert len(results) == 0, "Should return empty list when no WeChat running"
    
    def test_wechat_not_logged_in(self):
        """Test behavior when WeChat is running but not logged in."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1234, "name": "WeChat.exe"}
        mock_proc.pid = 1234
        mock_proc.open_files.return_value = []  # No Media.db opened
        
        with patch('psutil.process_iter', return_value=[mock_proc]):
            results = wechat_process.discover_wechat_keys()
            assert len(results) == 0, "Should return empty when WeChat not logged in"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--log-cli-level=DEBUG"])
