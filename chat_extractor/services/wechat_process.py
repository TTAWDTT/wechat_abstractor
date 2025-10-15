from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Any

from .wechat_crypto import verify_sqlcipher_password

LOGGER = logging.getLogger(__name__)

if os.name == "nt":  # Windows-specific imports
    import ctypes
    from ctypes import wintypes

    try:
        import psutil
    except ImportError:  # pragma: no cover - dependency may be missing until installed.
        psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = psutil is not None
else:  # pragma: no cover - non-Windows platforms are unsupported here.
    ctypes = None  # type: ignore[assignment]
    wintypes = None  # type: ignore[assignment]
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value if os.name == "nt" else -1  # type: ignore[arg-type]

_DEVICE_SYMBOLS = (
    b"android" + b"\x00" * 9 + b"\x07\x00\x00\x00",
    b"pad-android" + b"\x00" * 7 + b"\x0B\x00\x00\x00",
    b"iphone" + b"\x00" * 10 + b"\x06\x00\x00\x00",
    b"ipad" + b"\x00" * 12 + b"\x04\x00\x00\x00",
    b"OHOS" + b"\x00" * 12 + b"\x04\x00\x00\x00",
)


@dataclass(slots=True)
class WeChatKeyInfo:
    pid: int
    account: str
    base_path: Path
    media_db: Path
    key_hex: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "pid": self.pid,
            "account": self.account,
            "base_path": str(self.base_path),
            "media_db": str(self.media_db),
            "key_hex": self.key_hex,
        }


@dataclass
class _ProcessContext:
    pid: int
    base_path: Path
    media_db: Path
    account: str
    dll_base: int
    dll_size: int
    is_64bit: bool
    dll_version: str = ""


def discover_wechat_keys() -> List[WeChatKeyInfo]:
    """Discover all running WeChat processes and extract their encryption keys.
    
    This is the main entry point that mimics Go's GetWeChatAllInfo() workflow:
    1. Enumerate all processes to find WeChat.exe instances
    2. For each instance, extract process info (PID, account, DLL info)
    3. Extract encryption key from process memory
    
    Returns:
        List of WeChatKeyInfo objects containing PID, account, paths, and hex key
    """
    if os.name != "nt" or ctypes is None or psutil is None:
        LOGGER.warning("WeChat key discovery only supported on Windows with psutil")
        return []

    LOGGER.info("=" * 60)
    LOGGER.info("Starting WeChat key discovery")
    LOGGER.info("=" * 60)
    
    results: list[WeChatKeyInfo] = []
    wechat_count = 0
    
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if (proc.info.get("name") or "").lower() != "wechat.exe":
                continue
            wechat_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        LOGGER.info("\n" + "=" * 60)
        LOGGER.info("Found WeChat.exe instance #%d - PID: %d", wechat_count, proc.pid)
        LOGGER.info("=" * 60)
        
        context = _build_process_context(proc)
        if not context:
            LOGGER.warning("Failed to build process context for PID %d", proc.pid)
            continue

        key_hex = _extract_key_hex(context)
        if not key_hex:
            LOGGER.error("Failed to extract key for PID %d (Account: %s)", 
                        context.pid, context.account)
            continue

        info = WeChatKeyInfo(
            pid=context.pid,
            account=context.account,
            base_path=context.base_path,
            media_db=context.media_db,
            key_hex=key_hex,
        )
        results.append(info)
        LOGGER.info("✓ Successfully captured key for account: %s", context.account)

    LOGGER.info("\n" + "=" * 60)
    LOGGER.info("Key discovery complete: Found %d WeChat instances, extracted %d keys", 
               wechat_count, len(results))
    LOGGER.info("=" * 60)
    return results


def _build_process_context(proc: Any) -> _ProcessContext | None:
    try:
        open_files = proc.open_files()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None

    media_path: Path | None = None
    for entry in open_files:
        path = Path(entry.path)
        if path.name.lower() == "media.db" and path.parent.name.lower() == "msg":
            media_path = path
            break

    if not media_path:
        return None

    if media_path.parent is None or media_path.parent.parent is None:
        return None

    base_path = media_path.parent.parent
    account = base_path.name

    dll_base, dll_size, dll_version = _locate_wechat_dll(proc.pid)
    if not dll_base or not dll_size:
        return None

    is_64bit = _is_64bit_process(proc.pid)

    return _ProcessContext(
        pid=proc.pid,
        base_path=base_path,
        media_db=media_path,
        account=account,
        dll_base=dll_base,
        dll_size=dll_size,
        is_64bit=is_64bit,
        dll_version=dll_version,
    )


def _locate_wechat_dll(pid: int) -> tuple[int, int, str]:
    """Locate WeChatWin.dll and extract version info.
    
    Returns:
        tuple[int, int, str]: (base_address, dll_size, version_string)
    """
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(  # type: ignore[union-attr]
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if snapshot == INVALID_HANDLE_VALUE:
        return 0, 0, ""

    try:
        class MODULEENTRY32(ctypes.Structure):  # type: ignore[misc]
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", wintypes.HMODULE),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260),
            ]

        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        success = ctypes.windll.kernel32.Module32FirstW(snapshot, ctypes.byref(entry))  # type: ignore[union-attr]
        while success:
            module_name = entry.szModule.rstrip("\x00").lower()
            if module_name == "wechatwin.dll":
                base_addr = int(entry.modBaseAddr)
                dll_size = int(entry.modBaseSize)
                dll_path = entry.szExePath.rstrip("\x00")
                version = _extract_dll_version(dll_path)
                LOGGER.info(
                    "Found WeChatWin.dll - PID: %d, Base: 0x%08X, Size: %d, Version: %s",
                    pid, base_addr, dll_size, version
                )
                return base_addr, dll_size, version
            success = ctypes.windll.kernel32.Module32NextW(snapshot, ctypes.byref(entry))  # type: ignore[union-attr]
    finally:
        ctypes.windll.kernel32.CloseHandle(snapshot)  # type: ignore[union-attr]

    return 0, 0, ""


def _extract_dll_version(dll_path: str) -> str:
    """Extract version information from DLL file.
    
    This mimics Go's GetFileVersionInfo logic to extract the version string.
    """
    try:
        # Get version info size
        size = ctypes.windll.version.GetFileVersionInfoSizeW(dll_path, None)  # type: ignore[union-attr]
        if size == 0:
            return ""
        
        # Allocate buffer and get version info
        buffer = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(dll_path, 0, size, buffer):  # type: ignore[union-attr]
            return ""
        
        # Query fixed file info structure
        value = ctypes.c_void_p()
        value_size = wintypes.UINT()
        if not ctypes.windll.version.VerQueryValueW(  # type: ignore[union-attr]
            buffer, "\\", ctypes.byref(value), ctypes.byref(value_size)
        ):
            return ""
        
        # Parse VS_FIXEDFILEINFO structure
        # typedef struct tagVS_FIXEDFILEINFO {
        #   DWORD dwFileVersionMS;  // offset 8
        #   DWORD dwFileVersionLS;  // offset 12
        # }
        if value_size.value >= 52:  # VS_FIXEDFILEINFO is 52 bytes
            file_info = ctypes.cast(value, ctypes.POINTER(ctypes.c_uint32))
            version_ms = file_info[2]  # dwFileVersionMS at offset 8 (2 * 4 bytes)
            version_ls = file_info[3]  # dwFileVersionLS at offset 12 (3 * 4 bytes)
            
            major = (version_ms >> 16) & 0xFFFF
            minor = version_ms & 0xFFFF
            build = (version_ls >> 16) & 0xFFFF
            revision = version_ls & 0xFFFF
            
            return f"{major}.{minor}.{build}.{revision}"
    except Exception as e:
        LOGGER.debug("Failed to extract DLL version: %s", e)
    
    return ""


def _is_64bit_process(pid: int) -> bool:
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)  # type: ignore[union-attr]
    if not handle:
        return False
    try:
        is_wow64 = wintypes.BOOL()
        result = ctypes.windll.kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))  # type: ignore[union-attr]
        if result == 0:
            return True
        return not bool(is_wow64.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[union-attr]


def _extract_key_hex(context: _ProcessContext) -> str | None:
    """Extract encryption key from WeChat process memory.
    
    This is the main key extraction function that mimics Go's GetWeChatKey():
    1. Opens process and reads entire WeChatWin.dll memory
    2. Searches for device symbols (android/iphone/ipad/OHOS)
    3. For each symbol found, searches backwards for key pointer candidates
    4. Validates each candidate against Media.db
    
    Args:
        context: Process context with all necessary info
    
    Returns:
        Hex-encoded key string if found, None otherwise
    """
    LOGGER.info(
        "Starting key extraction - PID: %d, Account: %s, Version: %s, Is64Bit: %s",
        context.pid, context.account, context.dll_version or "unknown", context.is_64bit
    )
    
    handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[union-attr]
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, context.pid
    )
    if not handle:
        LOGGER.error("Failed to open process %d for memory reading", context.pid)
        return None
    
    try:
        try:
            buffer = (ctypes.c_ubyte * context.dll_size)()
        except (OverflowError, ValueError) as e:
            LOGGER.error("DLL buffer allocation failed for size %d: %s", context.dll_size, e)
            return None
        
        bytes_read = ctypes.c_size_t()
        success = ctypes.windll.kernel32.ReadProcessMemory(  # type: ignore[union-attr]
            handle,
            ctypes.c_void_p(context.dll_base),
            buffer,
            context.dll_size,
            ctypes.byref(bytes_read),
        )
        if not success:
            LOGGER.error("ReadProcessMemory failed for PID %d", context.pid)
            return None
        
        data = bytes(memoryview(buffer)[: bytes_read.value])
        LOGGER.info("Successfully read %d bytes from WeChatWin.dll", bytes_read.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[union-attr]

    # Search for device symbols and extract keys (matches Go's loop logic)
    offset = 0
    iteration = 0
    while offset < len(data):
        iteration += 1
        index = _find_device_symbol(data[offset:])
        if index == -1:
            LOGGER.debug("No more device symbols found after offset 0x%08X", offset)
            break
        
        absolute_offset = offset + index
        LOGGER.info("Iteration %d: Found device symbol at absolute offset 0x%08X", 
                   iteration, absolute_offset)
        
        # Search region BEFORE the device symbol for key pointers
        region = data[offset : offset + index]
        LOGGER.debug("Searching region from 0x%08X to 0x%08X (%d bytes)",
                    offset, offset + index, len(region))
        
        keys = _find_key_pointer_candidates(region, context.is_64bit)
        if keys:
            key_hex = _probe_keys(context, keys)
            if key_hex:
                LOGGER.info("✓ Successfully extracted key: %s", key_hex)
                return key_hex
        else:
            LOGGER.debug("No key pointer candidates found in this region")
        
        # Move past this symbol (matches Go's offset += (index + 20))
        offset += index + 20
        LOGGER.debug("Moving to next region at offset 0x%08X", offset)

    LOGGER.warning("Key extraction failed - no valid key found after %d iterations", iteration)
    return None


def _find_device_symbol(buffer: bytes) -> int:
    """Find device symbol in DLL memory to locate key region.
    
    Matches Go's hasDeviceSybmol() implementation with 5 device types:
    - android
    - pad-android
    - iphone
    - ipad
    - OHOS
    
    Returns:
        Index of first matching symbol in buffer (earliest occurrence), or -1 if none found
    """
    earliest_idx = -1
    earliest_symbol = None
    
    for symbol in _DEVICE_SYMBOLS:
        idx = buffer.find(symbol)
        if idx != -1:
            if earliest_idx == -1 or idx < earliest_idx:
                earliest_idx = idx
                earliest_symbol = symbol
    
    if earliest_idx != -1:
        LOGGER.debug("Found device symbol %r at offset 0x%08X", earliest_symbol, earliest_idx)
    
    return earliest_idx


def _find_key_pointer_candidates(buffer: bytes, is_64bit: bool) -> list[int]:
    """Find potential key pointer addresses in DLL memory.
    
    This mimics Go's findDBKeyPtr() logic with enhancements:
    - Searches backwards from buffer end
    - Checks ALL possible alignments (not just one) to avoid missing candidates
    - Looks for 0x20 (32 bytes) length marker
    - Extracts pointer address before the length marker
    
    Args:
        buffer: Memory buffer to search
        is_64bit: Whether process is 64-bit (determines pointer size)
    
    Returns:
        List of candidate pointer addresses
    """
    step = 8 if is_64bit else 4
    # Key length marker: 0x20 (32 bytes) in little-endian
    key_len_marker = b"\x20\x00\x00\x00\x00\x00\x00\x00" if is_64bit else b"\x20\x00\x00\x00"
    
    candidates: list[int] = []
    seen_addresses = set()

    # Check all possible alignments to ensure we don't miss candidates
    # This is more robust than Go's single-alignment approach
    for start_alignment in range(step):
        offset = len(buffer) - step - start_alignment
        while offset > 0:
            # Check bounds to avoid index errors
            if offset + step > len(buffer):
                offset -= step
                continue
                
            # Go uses bytes.Contains to check if keyLen is in buffer[offset:offset+step]
            segment = buffer[offset : offset + step]
            if key_len_marker in segment:  # Python 'in' operator is equivalent to bytes.Contains
                ptr_bytes = buffer[offset - step : offset]
                if len(ptr_bytes) == step:
                    addr = int.from_bytes(ptr_bytes, "little")
                    if addr not in seen_addresses:
                        seen_addresses.add(addr)
                        candidates.append(addr)
                        LOGGER.debug("Found key pointer candidate: 0x%08X at offset 0x%08X", addr, offset - step)
            
            offset -= step

    LOGGER.info("Found %d key pointer candidates", len(candidates))
    return candidates


def _probe_keys(context: _ProcessContext, addresses: list[int]) -> str | None:
    """Test each candidate key address by reading memory and verifying against database.
    
    This mimics Go's findDBkey() logic:
    - Opens process with read permissions
    - Reads 32 bytes from each candidate address
    - Validates against Media.db using SQLCipher verification
    
    Args:
        context: Process context with PID and Media.db path
        addresses: List of candidate pointer addresses to probe
    
    Returns:
        Hex-encoded key string if found, None otherwise
    """
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, context.pid
    )  # type: ignore[union-attr]
    if not handle:
        LOGGER.warning("Failed to open process %d for key probing", context.pid)
        return None

    try:
        LOGGER.info("Probing %d key candidates for PID %d", len(addresses), context.pid)
        for idx, address in enumerate(addresses):
            if address == 0:
                LOGGER.debug("Skipping null address at index %d", idx)
                continue
            
            LOGGER.debug("Probing key candidate %d/%d: keyAddrPtr=0x%08X", 
                        idx + 1, len(addresses), address)
            
            buffer = (ctypes.c_ubyte * 32)()
            bytes_read = ctypes.c_size_t()
            success = ctypes.windll.kernel32.ReadProcessMemory(  # type: ignore[union-attr]
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(buffer),
                32,
                ctypes.byref(bytes_read),
            )
            if not success:
                LOGGER.debug("ReadProcessMemory failed for address 0x%08X", address)
                continue
            if bytes_read.value != 32:
                LOGGER.debug("Read %d bytes (expected 32) from 0x%08X", bytes_read.value, address)
                continue
            
            key = bytes(buffer)
            LOGGER.debug("Testing key candidate: %s...", key[:8].hex())
            
            if verify_sqlcipher_password(context.media_db, key):
                key_hex = key.hex()
                LOGGER.info("✓ Valid key found at 0x%08X: %s", address, key_hex)
                return key_hex
            else:
                LOGGER.debug("✗ Key verification failed for 0x%08X", address)
        
        LOGGER.warning("No valid key found among %d candidates", len(addresses))
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[union-attr]

    return None
