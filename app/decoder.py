from __future__ import annotations

import hashlib
import io
import warnings

import cv2
import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

try:
    import zxingcpp  # type: ignore
except ImportError:  # Optional second decoder; OpenCV remains the local fallback.
    zxingcpp = None


MAX_IMAGE_BYTES = 12 * 1024 * 1024
MAX_PIXELS = 25_000_000
ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "BMP", "TIFF"}
Image.MAX_IMAGE_PIXELS = MAX_PIXELS


class DecodeError(ValueError):
    pass


def _polygon_area(points: np.ndarray) -> float:
    x = points[:, 0]
    y = points[:, 1]
    return abs(float(np.dot(x, np.roll(y, 1)) - np.dot(y, np.roll(x, 1)))) / 2


def _image_evidence(frame: np.ndarray, corners: list[np.ndarray], original: dict, pad: int) -> dict:
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    blur = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    contrast = float(gray.std())
    flags: list[str] = []
    if blur < 45:
        flags.append("low_sharpness")
    if contrast < 28:
        flags.append("low_contrast")
    if min(original["width"], original["height"]) < 120:
        flags.append("very_small_source")
    geometries: list[dict] = []
    inner_h, inner_w = frame.shape[:2]
    inner_h -= pad * 2
    inner_w -= pad * 2
    for points in corners:
        pts = np.asarray(points, dtype=float).reshape(4, 2)
        sides = [float(np.linalg.norm(pts[i] - pts[(i + 1) % 4])) for i in range(4)]
        perspective = max(sides) / max(1.0, min(sides))
        area = _polygon_area(pts)
        natural_margin = min(
            float(pts[:, 0].min() - pad), float(pts[:, 1].min() - pad),
            float(pad + inner_w - pts[:, 0].max()), float(pad + inner_h - pts[:, 1].max()),
        ) / max(1.0, min(inner_h, inner_w))
        geometries.append({
            "area_percent": round(area / max(1.0, inner_w * inner_h) * 100, 2),
            "perspective_ratio": round(perspective, 3),
            "estimated_edge_margin_percent": round(natural_margin * 100, 2),
        })
        if perspective > 1.65:
            flags.append("strong_perspective_distortion")
        if natural_margin < 0.01:
            flags.append("qr_quiet_zone_may_be_clipped")
    return {
        **original,
        "sha256": None,
        "qr_count": len(corners),
        "sharpness_laplacian_variance": round(blur, 2),
        "contrast_standard_deviation": round(contrast, 2),
        "geometry": geometries,
        "quality_flags": sorted(set(flags)),
        "interpretation": "Image-quality indicators support decoding reliability; they do not prove whether a physical sticker was replaced.",
    }


def _format_codeword(data: int) -> int:
    value = data << 10
    while value.bit_length() >= 11:
        value ^= 0x537 << (value.bit_length() - 11)
    return ((data << 10) | value) ^ 0x5412


def _qr_structure(straight: np.ndarray) -> dict:
    matrix = np.asarray(straight)
    if matrix.ndim == 3:
        matrix = cv2.cvtColor(matrix, cv2.COLOR_BGR2GRAY)
    size = int(min(matrix.shape[:2]))
    dark = matrix[:size, :size] < 128
    center = dark[max(0, size // 2 - max(2, size // 10)):min(size, size // 2 + max(2, size // 10) + 1), max(0, size // 2 - max(2, size // 10)):min(size, size // 2 + max(2, size // 10) + 1)]
    center_dark = float(center.mean()) if center.size else 0.5
    timing = list(dark[6, 8:max(8, size - 8)]) + list(dark[8:max(8, size - 8), 6]) if size >= 21 else []
    alternations = sum(timing[index] != timing[index - 1] for index in range(1, len(timing)))
    result = {
        "module_dimension": size,
        "qr_version": (size - 17) // 4 if size >= 21 and (size - 17) % 4 == 0 else None,
        "dark_module_ratio": round(float(dark.mean()), 4),
        "center_uniformity": round(max(center_dark, 1 - center_dark), 4),
        "timing_alternation_ratio": round(alternations / max(1, len(timing) - 1), 4),
    }
    if size < 21:
        return result
    bits = []
    coords = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(i, 8) for i in range(5, -1, -1)]
    for row, col in coords:
        bits.append(1 if matrix[row, col] < 128 else 0)
    observed = sum(bit << (14 - index) for index, bit in enumerate(bits))
    candidates = []
    for value in (observed, int(f"{observed:015b}"[::-1], 2)):
        for data in range(32):
            candidates.append(((value ^ _format_codeword(data)).bit_count(), data))
    distance, data = min(candidates)
    if distance <= 3:
        result.update({
            "error_correction_level": {0b01: "L", 0b00: "M", 0b11: "Q", 0b10: "H"}[(data >> 3) & 0b11],
            "mask_pattern": data & 0b111,
            "format_bit_distance": distance,
            "format_information_valid": True,
        })
    else:
        result.update({"format_information_valid": False, "format_bit_distance": distance})
    return result


def decode_qr(image_bytes: bytes) -> tuple[list[str], str, dict]:
    """Decode one or more QR payloads without interpreting or opening them."""
    if not image_bytes:
        raise DecodeError("The uploaded file is empty.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise DecodeError("Image exceeds the 12 MB upload limit.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(image_bytes)) as probe:
                if (probe.format or "").upper() not in ALLOWED_FORMATS:
                    raise DecodeError("Unsupported image format. Use PNG, JPEG, WEBP, BMP, or single-page TIFF.")
                if probe.width <= 0 or probe.height <= 0 or probe.width * probe.height > MAX_PIXELS:
                    raise DecodeError("Image dimensions exceed the 25-megapixel limit.")
                if bool(getattr(probe, "is_animated", False)) or int(getattr(probe, "n_frames", 1)) != 1:
                    raise DecodeError("Animated or multi-frame images are not accepted.")
                probe.verify()
        with Image.open(io.BytesIO(image_bytes)) as src:
            original = {
                "format": src.format or "unknown",
                "width": src.width,
                "height": src.height,
                "mode": src.mode,
                "has_exif": bool(src.getexif()),
                "animated": False,
                "file_size_bytes": len(image_bytes),
            }
            src = ImageOps.exif_transpose(src)
            rgb = src.convert("RGB")
            frame = cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2BGR)
            if min(frame.shape[:2]) < 240:
                factor = max(2, 240 // min(frame.shape[:2]))
                frame = cv2.resize(frame, None, fx=factor, fy=factor, interpolation=cv2.INTER_NEAREST)
            # Add a synthetic white quiet zone when a screenshot crops too
            # tightly around the modules.
            pad = max(12, min(frame.shape[:2]) // 20)
            frame = cv2.copyMakeBorder(
                frame, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=(255, 255, 255)
            )
    except (UnidentifiedImageError, OSError, Image.DecompressionBombWarning, Image.DecompressionBombError) as exc:
        raise DecodeError("Unsupported or invalid image. Use PNG, JPEG, WEBP, BMP, or single-page TIFF.") from exc

    detector = cv2.QRCodeDetector()
    payloads: list[str] = []
    corners: list[np.ndarray] = []
    straight_codes: list[np.ndarray] = []

    try:
        ok, decoded, points, straight = detector.detectAndDecodeMulti(frame)
        if ok:
            payloads.extend(value for value in decoded if value)
            if points is not None:
                corners.extend(np.asarray(item) for item in points)
            if straight:
                straight_codes.extend(np.asarray(item) for item in straight if item is not None)
    except cv2.error:
        pass

    if not payloads:
        value, points, straight = detector.detectAndDecode(frame)
        if value:
            payloads.append(value)
            if points is not None:
                corners.append(np.asarray(points))
            if straight is not None:
                straight_codes.append(np.asarray(straight))

    if not payloads:
        # Upscaling helps with small, slightly blurred phone screenshots.
        scaled = cv2.resize(frame, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        value, points, straight = detector.detectAndDecode(scaled)
        if value:
            payloads.append(value)
            if points is not None:
                corners.append(np.asarray(points) / 2.0)
            if straight is not None:
                straight_codes.append(np.asarray(straight))

    opencv_unique = list(dict.fromkeys(payloads))
    zxing_payloads: list[str] = []
    zxing_metadata: list[dict] = []
    if zxingcpp is not None:
        try:
            qr_formats = (
                zxingcpp.BarcodeFormat.QRCode |
                zxingcpp.BarcodeFormat.MicroQRCode |
                zxingcpp.BarcodeFormat.RMQRCode
            )
            for barcode in zxingcpp.read_barcodes(np.asarray(rgb), formats=qr_formats):
                text = str(getattr(barcode, "text", "") or "")
                if text:
                    zxing_payloads.append(text)
                    raw_bytes = bytes(getattr(barcode, "bytes", b"") or b"")
                    zxing_metadata.append({
                        "format": str(getattr(barcode, "format", "QR Code")),
                        "content_type": str(getattr(barcode, "content_type", "Text")),
                        "raw_bytes_sha256": hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else None,
                        "raw_bytes_length": len(raw_bytes),
                    })
        except (RuntimeError, ValueError, TypeError, OSError):
            zxing_metadata = [{"error": "decoder_failed"}]
    unique = list(dict.fromkeys(opencv_unique + zxing_payloads))
    if not unique:
        raise DecodeError(
            "No readable QR code was found. Try a sharper image with the full code and quiet border visible."
        )
    digest = hashlib.sha256(image_bytes).hexdigest()
    evidence = _image_evidence(frame, corners[:8], original, pad)
    evidence["detected_geometry_count"] = len(corners)
    evidence["qr_count"] = min(8, len(unique))
    evidence["sha256"] = digest
    evidence["multiple_qr_codes"] = len(unique) > 1
    evidence["decoders"] = {
        "opencv": {"available": True, "decoded_count": len(opencv_unique)},
        "zxing_cpp": {"available": zxingcpp is not None, "decoded_count": len(set(zxing_payloads)), "metadata": zxing_metadata},
    }
    evidence["qr_structure"] = [_qr_structure(item) for item in straight_codes[:8]]
    if any(item.get("center_uniformity", 0) >= 0.92 for item in evidence["qr_structure"]):
        evidence["quality_flags"].append("possible_central_overlay")
    evidence["decoder_consensus"] = (
        "agreed" if zxingcpp is not None and set(opencv_unique) == set(zxing_payloads) else
        "disagreed" if zxingcpp is not None and opencv_unique and zxing_payloads else
        "single_decoder"
    )
    if evidence["decoder_consensus"] == "disagreed":
        evidence["quality_flags"].append("decoder_disagreement")
    return unique[:8], digest, evidence
