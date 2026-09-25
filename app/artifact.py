from __future__ import annotations

import hashlib
import html
import os
import shutil

# Only fixed local Poppler/Tesseract executables are invoked.
import subprocess  # nosec B404
import tempfile
from email import policy
from email.errors import MessageError
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

from .decoder import MAX_IMAGE_BYTES, DecodeError, decode_qr

MAX_ARTIFACT_BYTES = 20 * 1024 * 1024
MAX_PDF_PAGES = 10
MAX_EMAIL_ATTACHMENTS = 20


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _html_text(value: str) -> str:
    parser = _TextExtractor()
    parser.feed(value)
    return html.unescape(" ".join(parser.parts))


def _ocr_image(data: bytes) -> tuple[str, dict]:
    if os.getenv("QR_SHIELD_OCR") != "1":
        return "", {"enabled": False}
    binary = shutil.which("tesseract")
    if not binary:
        return "", {"enabled": True, "available": False}
    try:
        # The executable path and argv are fixed; shell execution is disabled.
        completed = subprocess.run(  # nosec B603
            [binary, "stdin", "stdout", "--psm", "6"], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"},
            check=False,
        )
        text = completed.stdout.decode("utf-8", "replace")[:32768] if completed.returncode == 0 else ""
        return text, {"enabled": True, "available": True, "character_count": len(text), "text_sha256": hashlib.sha256(text.encode()).hexdigest() if text else None}
    except (OSError, subprocess.TimeoutExpired):
        return "", {"enabled": True, "available": True, "error": "ocr_failed_or_timed_out"}


def _decode_image(data: bytes, context: str = "", source: dict | None = None) -> list[dict]:
    payloads, digest, evidence = decode_qr(data)
    ocr_text, ocr_meta = _ocr_image(data)
    evidence["ocr"] = ocr_meta
    if source:
        evidence["source"] = source
    combined = "\n".join(part for part in (context, ocr_text) if part)[:32768]
    return [{"payload": payload, "sha256": digest, "image_analysis": evidence, "context_text": combined} for payload in payloads]


def _run_pdf_tool(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    # Callers provide fixed local tools and private temporary paths.
    return subprocess.run(  # nosec B603
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"},
        check=False,
    )


def _decode_pdf(data: bytes) -> list[dict]:
    pdftoppm, pdftotext = shutil.which("pdftoppm"), shutil.which("pdftotext")
    if not pdftoppm:
        raise DecodeError("PDF support requires the local Poppler pdftoppm utility.")
    container_hash = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix="qrshield-pdf-") as folder:
        root = Path(folder)
        source = root / "evidence.pdf"
        source.write_bytes(data)
        context = ""
        if pdftotext:
            text_path = root / "context.txt"
            extracted = _run_pdf_tool([pdftotext, "-f", "1", "-l", str(MAX_PDF_PAGES), "-enc", "UTF-8", "-layout", str(source), str(text_path)], 12)
            if extracted.returncode == 0:
                try:
                    with text_path.open(encoding="utf-8", errors="replace") as handle:
                        context = handle.read(32768)
                except OSError:
                    context = ""
        prefix = root / "page"
        rendered = _run_pdf_tool([pdftoppm, "-f", "1", "-l", str(MAX_PDF_PAGES), "-r", "160", "-png", str(source), str(prefix)], 25)
        if rendered.returncode != 0:
            raise DecodeError("The PDF could not be safely rasterized.")
        results: list[dict] = []
        for page, path in enumerate(sorted(root.glob("page-*.png")), 1):
            try:
                results.extend(_decode_image(path.read_bytes(), context, {"container": "PDF", "container_sha256": container_hash, "page": page}))
            except DecodeError:
                continue
        if not results:
            raise DecodeError("No readable QR code was found in the first 10 PDF pages.")
        return results


def _decode_email(data: bytes) -> list[dict]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except (MessageError, ValueError, TypeError, UnicodeError) as exc:
        raise DecodeError("The email message could not be parsed safely.") from exc
    text_parts: list[str] = [str(message.get("Subject", ""))]
    attachments: list[tuple[str, bytes]] = []
    for part in message.walk():
        ctype = part.get_content_type().casefold()
        disposition = (part.get_content_disposition() or "").casefold()
        if ctype == "text/plain" and disposition != "attachment":
            try: text_parts.append(part.get_content())
            except (LookupError, UnicodeError, TypeError, ValueError, AttributeError):
                continue
        elif ctype == "text/html" and disposition != "attachment":
            try: text_parts.append(_html_text(part.get_content()))
            except (LookupError, UnicodeError, TypeError, ValueError, AttributeError):
                continue
        elif ctype.startswith("image/") and len(attachments) < MAX_EMAIL_ATTACHMENTS:
            payload = part.get_payload(decode=True) or b""
            if 0 < len(payload) <= MAX_IMAGE_BYTES:
                attachments.append((part.get_filename() or "image", payload))
    context = "\n".join(text_parts)[:32768]
    container_hash = hashlib.sha256(data).hexdigest()
    results: list[dict] = []
    for index, (name, image) in enumerate(attachments, 1):
        try:
            results.extend(_decode_image(image, context, {"container": "EML", "container_sha256": container_hash, "attachment": index, "filename_sha256": hashlib.sha256(name.encode()).hexdigest()}))
        except DecodeError:
            continue
    if not results:
        raise DecodeError("No readable QR code was found in supported email image attachments.")
    return results


def decode_artifact(data: bytes, filename: str = "", content_type: str = "") -> list[dict]:
    if not data:
        raise DecodeError("The uploaded file is empty.")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise DecodeError("Artifact exceeds the 20 MB upload limit.")
    lower = filename.casefold()
    ctype = content_type.casefold()
    if data.startswith(b"%PDF-") or lower.endswith(".pdf") or ctype == "application/pdf":
        return _decode_pdf(data)
    if lower.endswith(".eml") or ctype in {"message/rfc822", "application/eml"}:
        return _decode_email(data)
    return _decode_image(data)
