from app.collectors.dns import collect_dns

from unittest.mock import MagicMock

from app.collectors.dns import _normalize_mx_answer


def test_normalize_mx_answer_returns_mail_server():
    answer = MagicMock()

    answer.exchange = "mail.example.com."

    result = _normalize_mx_answer(
        answer
    )

    assert result == "mail.example.com"


def test_normalize_mx_answer_ignores_null_mx():
    answer = MagicMock()

    answer.exchange = "."

    result = _normalize_mx_answer(
        answer
    )

    assert result is None


def test_collect_dns_returns_expected_structure():
    result = collect_dns("example.com")

    assert result["domain"] == "example.com"
    assert "records" in result

    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        assert record_type in result["records"]
        assert isinstance(result["records"][record_type], list)