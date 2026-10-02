from unittest.mock import Mock, patch

from app.collectors.crtsh import (
    _extract_domains,
    _is_valid_dns_name,
    collect_certificates,
)


def test_extract_domains_normalizes_and_deduplicates():
    entries = [
        {
            "name_value": "*.example.com\napi.example.com"
        },
        {
            "name_value": "api.example.com\nmail.example.com"
        },
    ]

    result = _extract_domains(entries)

    assert result == [
        "api.example.com",
        "example.com",
        "mail.example.com",
    ]


def test_collect_certificates_retries_on_502():
    failed_response = Mock()
    failed_response.status_code = 502

    successful_response = Mock()
    successful_response.status_code = 200
    successful_response.json.return_value = [
        {
            "name_value": (
                "example.com\n"
                "www.example.com"
            ),
        }
    ]

    with patch(
        "app.collectors.crtsh.requests.get",
        side_effect=[
            failed_response,
            failed_response,
            successful_response,
        ],
    ) as mock_get, patch(
        "app.collectors.crtsh.time.sleep"
    ) as mock_sleep:

        result = collect_certificates("example.com")

    assert result["error"] is None

    assert result["domains"] == [
        "example.com",
        "www.example.com",
    ]

    assert mock_get.call_count == 3

    assert mock_sleep.call_count == 2

    mock_sleep.assert_any_call(1)
    mock_sleep.assert_any_call(2)


def test_is_valid_dns_name_accepts_valid_names():
    assert _is_valid_dns_name(
        "example.com"
    )

    assert _is_valid_dns_name(
        "api.example.com"
    )

    assert _is_valid_dns_name(
        "*.example.com"
    )


def test_is_valid_dns_name_rejects_invalid_names():
    assert not _is_valid_dns_name(
        "subjectname@example.com"
    )

    assert not _is_valid_dns_name(
        "as207960 test intermediate - example.com"
    )

    assert not _is_valid_dns_name(
        "example"
    )

    assert not _is_valid_dns_name(
        "foo..example.com"
    )


def test_extract_domains_filters_invalid_values():
    entries = [
        {
            "name_value": (
                "example.com\n"
                "api.example.com\n"
                "subjectname@example.com\n"
                "as207960 test intermediate - example.com\n"
                "*.example.com"
            )
        }
    ]

    result = _extract_domains(entries)

    assert result == [
        "api.example.com",
        "example.com",
    ]