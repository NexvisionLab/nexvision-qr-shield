import cv2
import pytest

from app.decoder import DecodeError, decode_qr


def qr_png(payload: str) -> bytes:
    encoder = cv2.QRCodeEncoder_create()
    image = encoder.encode(payload)
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    return encoded.tobytes()


def test_decode_generated_qr():
    payloads, digest, evidence = decode_qr(qr_png("https://example.com/test"))
    assert payloads == ["https://example.com/test"]
    assert len(digest) == 64
    assert evidence["qr_count"] >= 1
    assert evidence["qr_structure"][0]["module_dimension"] >= 21
    assert evidence["qr_structure"][0]["qr_version"] >= 1
    assert evidence["decoders"]["opencv"]["available"] is True


def test_rejects_invalid_image():
    with pytest.raises(DecodeError):
        decode_qr(b"not an image")
