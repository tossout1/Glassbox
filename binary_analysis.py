"""Bounded, read-only inspection of arbitrary uploaded bytes."""
import hashlib
import math
from collections import Counter

SIGNATURES = (
    (b"\x7fELF", "ELF executable/shared object"),
    (b"MZ", "DOS/Windows PE candidate"),
    (b"\x00asm", "WebAssembly module"),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O universal binary candidate"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little-endian binary"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP-compatible archive"),
    (b"\x1f\x8b", "GZIP-compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\xfd7zXZ\x00", "XZ-compressed data"),
    (b"BZh", "BZIP2-compressed data"),
    (b"SQLite format 3\x00", "SQLite database"),
)


def inspect_binary(path, sample_limit=65536):
    """Inspect a small sample; stream the full file only for its SHA-256."""
    digest = hashlib.sha256()
    size = 0
    sample = bytearray()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if len(sample) < sample_limit:
                sample.extend(chunk[:sample_limit - len(sample)])
    raw = bytes(sample)
    signature = next((name for prefix, name in SIGNATURES if raw.startswith(prefix)),
                     "Unknown or unrecognized signature")
    if raw.startswith(b"RIFF") and raw[8:12] == b"WEBP":
        signature = "WebP image"
    if len(raw) >= 12 and raw[4:8] == b"ftyp":
        signature = "ISO base media format (e.g. HEIF/AVIF/MP4)"
    if raw:
        counts = Counter(raw)
        entropy = -sum((count / len(raw)) * math.log2(count / len(raw))
                       for count in counts.values())
    else:
        entropy = 0.0
    # Preview is hex only: never decode or execute untrusted bytes.
    return ("BINARY INSPECTION\n"
            f"Bytes: {size}\n"
            f"SHA-256: {digest.hexdigest()}\n"
            f"Signature: {signature}\n"
            f"First {min(64, len(raw))} bytes (hex): {raw[:64].hex(' ')}\n"
            f"Sample entropy: {entropy:.2f}/8 bits per byte "
            f"(first {len(raw)} bytes; not a malware verdict)\n"
            "Inspection method: read-only; unsupported formats are still inspected as raw bytes.")
