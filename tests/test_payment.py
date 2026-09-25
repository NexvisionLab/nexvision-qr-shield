from app.payment import TLVError, analyze_emv_qr, crc16_ccitt_false, parse_tlv


def make_payload(prefix: str) -> str:
    with_crc_tag = prefix + "6304"
    return with_crc_tag + crc16_ccitt_false(with_crc_tag)


def test_crc_known_standard_vector_shape():
    payload = make_payload("0002010102115204000053037025802SG5904TEST6009SINGAPORE")
    result = analyze_emv_qr(payload)
    assert result["valid_tlv"] is True
    assert result["crc_valid"] is True
    assert result["country"] == "SG"


def test_tlv_rejects_truncation():
    try:
        parse_tlv("0005ABC")
    except TLVError as exc:
        assert "beyond payload" in str(exc)
    else:
        raise AssertionError("Expected malformed TLV to fail")


def test_tlv_lengths_are_utf8_bytes():
    fields = parse_tlv("5906商户")
    assert fields[0]["value"] == "商户"
