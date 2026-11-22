"""Uploaded PCAP files are UNTRUSTED input: check name, size and file signature before parsing."""

import hashlib
import re
import secrets
from pathlib import Path

from fastapi import HTTPException, UploadFile

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
# First 4 bytes ("magic number") of real capture files.
CAPTURE_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # pcapng (Section Header Block)
}
CHUNK = 1024 * 1024


def clean_filename(name: str | None) -> str:
    """Keep only a safe display name: no folders, no control characters, max 200 chars.
    It is only stored for display; it is NEVER used to build a path on disk."""
    base = Path(name or "capture").name
    base = re.sub(r"[^\w.\- ]", "_", base)[:200]
    return base or "capture"


def save_upload(upload: UploadFile, upload_dir: Path, max_bytes: int) -> tuple[Path, str, int]:
    """Copy the upload to a random temporary file. Returns (path, sha256, size)."""
    name = clean_filename(upload.filename)
    if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, f"Only {sorted(ALLOWED_EXTENSIONS)} files are accepted")

    upload_dir.mkdir(parents=True, exist_ok=True)
    path = upload_dir / f"{secrets.token_hex(16)}.upload"  # random name, never the user's
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("wb") as out:
            while chunk := upload.file.read(CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(413, f"File larger than {max_bytes // (1024 * 1024)} MB")
                digest.update(chunk)
                out.write(chunk)
        with path.open("rb") as check:
            if check.read(4) not in CAPTURE_MAGIC:
                raise HTTPException(422, "Not a PCAP/PCAPNG file (wrong file signature)")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path, digest.hexdigest(), size
