import pytest
from pytz import utc
from datetime import datetime

from process_virus_scan_data import (
    format_date_utc,
    calculate_detections_by_vendors,
    VENDORS,
)


@pytest.fixture
def test_data():
    return {
        "scans": {
            "Webtest": {"detected": False},
            "TestVendor": {"detected": True},
            "CrowdStrike": {"detected": True},
            "Microsoft": {"detected": True},
            "McAfee": {"detected": True},
            "Symantec": {"detected": False},
        }
    }


def test_format_date_utc_no_timezone():
    timestamp = "2022-01-03 12:30:04"
    assert format_date_utc(timestamp) == datetime(2022, 1, 3, 12, 30, 4)


def test_format_date_utc_from_timezone():
    timestamp = "2022-01-03 14:30:04"
    assert format_date_utc(timestamp, "US/Central") == datetime(
        2022, 1, 3, 20, 30, 4, tzinfo=utc
    )


def test_calculate_detections_by_vendor(test_data):
    calculate_detections_by_vendors(test_data, VENDORS)
    assert test_data["Microsoft"] == 1
    assert test_data["McAfee"] == 1
    assert test_data["Symantec"] == 0
    assert test_data["total_detections"] == 2
    assert "scans" not in test_data
