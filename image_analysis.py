"""Static image inspection for Glassbox; never executes image contents."""
from pathlib import Path
import warnings


def inspect_image(path):
    """Return image metadata, None for nonimages, or an explicit decode error."""
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError:
        # Pillow is required to decode image formats.
        return None if Path(path).suffix.lower() not in {
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff",
            ".ico", ".icns", ".ppm", ".pgm", ".pbm", ".avif", ".heic", ".heif",
            ".dds", ".tga", ".pcx", ".psd", ".jp2", ".j2k", ".svg",
        } else "Image metadata unavailable: install Pillow (python3 -m pip install Pillow)."
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as img:
                width, height = img.size
                if width * height > 40_000_000:
                    return "Image detected, but pixel count exceeds the 40-megapixel inspection limit."
                fmt = img.format or "Unknown"
                mode = img.mode
                frames = getattr(img, "n_frames", 1)
                # Verify encoded data where the installed decoder supports it.
                img.verify()
        return (f"Image format: {fmt}\nDimensions: {width} x {height} pixels\n"
                f"Color mode: {mode}\nFrames/pages: {frames}\n"
                "Inspection: image header and encoded data validated; no image code executed.")
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError,
            Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        if Path(path).suffix.lower() in {
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff",
            ".ico", ".icns", ".ppm", ".pgm", ".pbm", ".avif", ".heic", ".heif",
            ".dds", ".tga", ".pcx", ".psd", ".jp2", ".j2k", ".svg",
        }:
            return f"Image inspection could not decode this file: {type(exc).__name__}: {exc}"
        return None
