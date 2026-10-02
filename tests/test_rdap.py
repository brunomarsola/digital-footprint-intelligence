from app.collectors.rdap import (
    _extract_events,
    _extract_nameservers,
)


def test_extract_nameservers():
    data = {
        "nameservers": [
            {"ldhName": "NS1.EXAMPLE.COM."},
            {"ldhName": "ns2.example.com."},
            {"ldhName": "NS1.EXAMPLE.COM."},
        ]
    }

    result = _extract_nameservers(data)

    assert result == [
        "ns1.example.com",
        "ns2.example.com",
    ]


def test_extract_events():
    data = {
        "events": [
            {
                "eventAction": "registration",
                "eventDate": "2020-01-01T00:00:00Z",
            },
            {
                "eventAction": "expiration",
                "eventDate": "2027-01-01T00:00:00Z",
            },
        ]
    }

    result = _extract_events(data)

    assert result == [
        {
            "action": "registration",
            "date": "2020-01-01T00:00:00Z",
        },
        {
            "action": "expiration",
            "date": "2027-01-01T00:00:00Z",
        },
    ]