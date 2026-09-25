from __future__ import annotations

import pytest

from app.analyzer import analyze_payload
from app.multilingual_intel import analyze_multilingual_text, scam_pack

POSITIVE_SAMPLES = [
    ("en", "Urgent action: your account will be suspended. Verify your account immediately."),
    ("ms", "Akaun anda akan disekat. Segera sahkan akaun anda."),
    ("id", "Paket gagal dikirim. Segera verifikasi dan bayar biaya pengiriman."),
    ("zh-hans", "您的账户将被暂停，请立即验证您的账户。"),
    ("zh-hant", "您的帳戶將被停用，請立即驗證您的帳戶。"),
    ("hi", "आपका खाता बंद कर दिया जाएगा। अभी सत्यापित करें और अपना खाता सत्यापित करें।"),
    ("bn", "আপনার অ্যাকাউন্ট বন্ধ করা হবে। এখনই যাচাই করুন এবং অ্যাকাউন্ট যাচাই করুন।"),
    ("ta", "உங்கள் கணக்கு முடக்கப்படும். உடனே சரிபார்க்கவும் மற்றும் கணக்கை சரிபார்க்கவும்."),
    ("ur", "آپ کا اکاؤنٹ بند کر دیا جائے گا۔ ابھی تصدیق کریں اور اپنے اکاؤنٹ کی تصدیق کریں۔"),
    ("ar", "سيتم تعليق حسابك. تحقق الآن وأدخل رمز التحقق."),
    ("th", "บัญชีของคุณจะถูกระงับ ยืนยันทันทีและยืนยันบัญชีของคุณ"),
    ("vi", "Tài khoản của bạn sẽ bị khóa. Xác minh ngay và xác minh tài khoản."),
    ("ja", "アカウントが停止されます。今すぐ確認して認証コードを入力。"),
    ("ko", "계정이 정지됩니다. 지금 확인하세요. 인증번호를 입력하세요."),
    ("es", "Su cuenta será suspendida. Verifique ahora y verifique su cuenta."),
    ("fr", "Votre compte sera suspendu. Vérifiez maintenant et vérifiez votre compte."),
    ("de", "Ihr Konto wird gesperrt. Jetzt bestätigen und bestätigen Sie Ihr Konto."),
    ("pt", "Sua conta será suspensa. Verifique agora e verifique sua conta."),
    ("fil", "Masususpinde ang iyong account. I-verify ngayon at i-verify ang iyong account."),
]


@pytest.mark.parametrize(("language", "text"), POSITIVE_SAMPLES)
def test_localized_combination_detected(language: str, text: str):
    findings, details = analyze_multilingual_text(text)
    assert "MULTILINGUAL_SOCIAL_ENGINEERING" in {item.code for item in findings}
    assert language in {item["code"] for item in details["language_signals"]}
    assert len(details["scam_categories"]) >= 2


@pytest.mark.parametrize("text", [
    "Account settings and payment options",
    "Your account is active. No action required.",
    "Scam awareness training: never share your OTP.",
    "Delivery menu and opening hours",
    "Payment accepted by card or cash",
    "Pelajari keselamatan digital dan laporkan penipuan.",
    "谨防诈骗，不要提供验证码。",
    "防詐騙：切勿透露驗證碼。",
    "لا تشارك رمز التحقق مع أي شخص.",
    "ระวังมิจฉาชีพและอย่าเปิดเผยรหัส",
    "Cảnh báo lừa đảo và hướng dẫn an toàn.",
    "詐欺に注意してください。",
    "사기 예방 교육 자료",
    "Alerta de estafa y consejos de seguridad.",
    "Prévention des arnaques et conseils de sécurité."
])
def test_benign_or_awareness_text_does_not_score(text: str):
    findings, _details = analyze_multilingual_text(text)
    assert not any(item.score > 0 for item in findings)


def test_awareness_context_suppresses_combined_phrases():
    text = "Scam awareness: an example may say act now and verify your account. No action required."
    findings, details = analyze_multilingual_text(text)
    assert {item.code for item in findings} == {"SCAM_AWARENESS_CONTEXT"}
    assert findings[0].score == 0
    assert details["awareness_context"]


def test_single_generic_signal_is_not_enough():
    findings, details = analyze_multilingual_text("Please verify your account")
    assert findings == []
    assert details["scam_categories"] == ["credentials"]


def test_parking_payment_lure_is_covered():
    findings, details = analyze_multilingual_text("Urgent action: pay parking fee now")
    assert "MULTILINGUAL_SOCIAL_ENGINEERING" in {item.code for item in findings}
    assert "parking" in details["scam_categories"]


def test_country_signal_is_qualified_not_geolocation():
    findings, details = analyze_multilingual_text("Singpass urgent action: unpaid fine, verify your account immediately")
    assert "COUNTRY_SCAM_PATTERN" in {item.code for item in findings}
    assert details["possible_country_signals"][0]["code"] == "SG"
    assert "not geolocation" in details["interpretation"]


def test_pack_is_offline_and_versioned():
    pack = scam_pack()
    assert pack["pack_id"] == "nexvision-multilingual-scam-policy"
    assert len(pack["languages"]) == 29
    assert "api" not in pack


@pytest.mark.asyncio
async def test_full_analyzer_exposes_multilingual_evidence_without_network(monkeypatch):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("network should not be used")

    monkeypatch.setattr("app.analyzer.resolve_public_ips", forbidden)
    result = await analyze_payload(
        "https://example.invalid/?msg=Su%20cuenta%20ser%C3%A1%20suspendida%20verifique%20ahora%20verifique%20su%20cuenta",
        network_checks=False,
    )
    assert "MULTILINGUAL_SOCIAL_ENGINEERING" in {item.code for item in result.findings}
    assert result.decoded_details["multilingual_intelligence"]["policy_pack"]["version"] == "2026.09.2"
    assert result.engine["external_api_required"] is False


@pytest.mark.asyncio
async def test_short_brand_is_not_matched_inside_unrelated_word():
    result = await analyze_payload("https://first.example/help", network_checks=False)
    assert "BRAND_IMPERSONATION" not in {item.code for item in result.findings}
