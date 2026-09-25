import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st

from app.analyzer import analyze_payload
from app.payment import TLVError, parse_tlv


@settings(max_examples=40, deadline=500)
@given(st.text(min_size=1, max_size=300))
def test_arbitrary_payload_never_crashes_or_returns_raw_exception(value):
    result = asyncio.run(analyze_payload(value))
    assert 0 <= result.score <= 100
    assert result.evidence_integrity.get("canonical_result_sha256")


@settings(max_examples=80, deadline=200)
@given(st.binary(min_size=0, max_size=200))
def test_tlv_parser_is_bounded_and_only_returns_or_raises_defined_error(raw):
    value = raw.decode("utf-8", "replace")
    try:
        fields = parse_tlv(value)
        assert sum(int(field["length"]) for field in fields) <= len(raw) * 3
    except TLVError:
        pass
