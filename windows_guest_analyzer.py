"""Windows guest-side static file inspection for Glassbox.

Run inside the Windows VM using Python 3. Does not execute uploaded samples.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

def analyze(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("Expected a regular file")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    with path.open("rb") as stream:
        header = stream.read(4096)
    kind = ("PE executable (MZ)" if header.startswith(b"MZ")
            else "ZIP-based format" if header.startswith(b"PK\\x03\\x04")
            else "Unknown / data")
    return {"filename": path.name, "size": path.stat().st_size,
            "sha256": h.hexdigest(), "file_type": kind,
            "execution": "NOT PERFORMED",
            "note": "Static inspection only. No safety verdict can be inferred."}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to file inside Windows guest")
    args = parser.parse_args()
    print(json.dumps(analyze(args.file), indent=2))
