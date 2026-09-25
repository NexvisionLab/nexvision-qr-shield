import cv2
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_text_api_without_network():
    response = client.post(
        "/api/analyze/text",
        json={"payload": "https://example.com", "network_checks": False},
    )
    assert response.status_code == 200
    assert response.json()["payload_type"] == "url"


def test_rejects_non_image_upload():
    response = client.post(
        "/api/analyze/image",
        files={"file": ("payload.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 415


def test_image_api_decodes_and_reports_evidence():
    image = cv2.QRCodeEncoder_create().encode("https://example.com")
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    response = client.post(
        "/api/analyze/image",
        files={"file": ("qr.png", encoded.tobytes(), "image/png")},
        data={"network_checks": "false"},
    )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["payload"] == "https://example.com"
    assert result["image_analysis"]["format"] == "PNG"
