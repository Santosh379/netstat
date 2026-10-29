import os
import uuid
from pathlib import Path
from fastapi import HTTPException, UploadFile
from ..config import settings

PCAP_MAGIC_NUMBERS = [
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big endian)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little endian)
    b"\xa1\xb2\xcd\x34",  # Modified pcap (big endian)
    b"\x34\xcd\xb2\xa1",  # Modified pcap (little endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG block type 0x0A0D0D0A
]

async def validate_and_save_pcap(upload_file: UploadFile) -> tuple[Path, str, int]:
    """
    Validates magic bytes, size limits, sanitizes filename, and writes to isolated temporary storage.
    Returns: (saved_path, original_filename, file_size)
    """
    if not upload_file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file missing filename")
    
    original_name = Path(upload_file.filename).name
    # Basic extension validation
    ext = Path(original_name).suffix.lower()
    if ext not in [".pcap", ".pcapng", ".cap"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension '{ext}'. Only .pcap and .pcapng files are supported."
        )

    # Read first 4 bytes to check magic signature
    header = await upload_file.read(4)
    if len(header) < 4 or header not in PCAP_MAGIC_NUMBERS:
        raise HTTPException(
            status_code=400,
            detail="Invalid PCAP file header. File is not a recognized PCAP or PCAPNG packet capture."
        )

    # Read remaining content while checking size limit
    unique_id = uuid.uuid4().hex
    safe_filename = f"capture_{unique_id}{ext}"
    target_path = settings.UPLOAD_DIR / safe_filename

    total_bytes = 4
    with open(target_path, "wb") as f:
        f.write(header)
        while chunk := await upload_file.read(1024 * 64):  # 64KB chunks
            total_bytes += len(chunk)
            if total_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
                f.close()
                if target_path.exists():
                    target_path.unlink()
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB"
                )
            f.write(chunk)

    return target_path, original_name, total_bytes

def safe_remove_file(file_path: Path) -> None:
    try:
        if file_path.exists():
            file_path.unlink()
    except Exception:
        pass
