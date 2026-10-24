"""Initial Windows file inspection path for Glassbox.

This stage does not start the Windows VM or execute samples. It performs
static checks while the guest transfer and telemetry channel is developed.
"""
import hashlib
from pathlib import Path

def inspect_windows_file(path, original_name):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    with path.open("rb") as stream:
        header = stream.read(4096)
    if header.startswith(b"MZ"):
        kind = "Windows PE candidate (MZ header)"
    elif header.startswith(bytes([80, 75, 3, 4])):
        kind = "ZIP-based file"
    elif header.startswith(b"#!"):
        kind = "Script with shebang"
    else:
        kind = "Unrecognized or data file"
    return chr(10).join([
        "GLASSBOX WINDOWS FILE INSPECTION",
        "Mode: STATIC ONLY (host-side)",
        f"File: {original_name}",
        f"Size: {path.stat().st_size} bytes",
        f"SHA-256: {digest.hexdigest()}",
        f"Type: {kind}",
        "",
        "Windows 11 ARM64 VM: installed separately; not launched for this scan.",
        "Dynamic execution: NOT PERFORMED",
        "Guest file transfer: NOT CONFIGURED",
        "Safety verdict: NOT AVAILABLE",
        "This inspection does not establish whether a file is safe.",
    ])
