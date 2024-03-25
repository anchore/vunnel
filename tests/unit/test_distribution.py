import json

import pytest
from datetime import datetime, timezone
from src.vunnel.distribution import ListingEntry, ListingDocument


class TestListingEntry:

    @pytest.fixture
    def entry1(self):
        return ListingEntry(
            built="2022-01-01T00:00:00Z",
            distribution_version=1,
            url="http://example.com/archive.tar.gz",
            distribution_checksum="sha256:1234567890abcdef1234567890abcdef",
            enclosed_checksum="xxhash64:1234567890abcdef",
        )

    @pytest.fixture
    def entry2(self):
        return ListingEntry(
            built="2022-01-01T00:00:00Z",
            distribution_version=1,
            url="http://example.com/archive.tar.zst",
            distribution_checksum="sha256:abcdef1234567890abcdef1234567890",
            enclosed_checksum="xxhash64:abcdef1234567890",
        )

    def test_basename(self, entry1, entry2):
        assert entry1.basename() == "archive.tar.gz"
        assert entry2.basename() == "archive.tar.zst"

    def test_basename_invalid_url(self, entry1):
        with pytest.raises(RuntimeError):
            entry1.url = "http://example.com/archive.tar.unsupported"
            entry1.basename()

    def test_age_in_days(self, entry1):
        now = datetime.now(tz=timezone.utc)
        assert entry1.age_in_days(now) == (now - datetime(2022, 1, 1, tzinfo=timezone.utc)).days

    def test_age_in_days_no_now(self, entry1):
        assert entry1.age_in_days() == (datetime.now(tz=timezone.utc) - datetime(2022, 1, 1, tzinfo=timezone.utc)).days


class TestListingDocument:
    @pytest.fixture
    def document(self):
        entries = [
            ListingEntry(
                built="2022-01-01T00:00:00Z",
                distribution_version=1,
                url="http://example.com/archive1.tar.gz",
                distribution_checksum="sha256:1234567890abcdef1234567890abcdef",
                enclosed_checksum="xxhash64:1234567890abcdef",
            ),
            ListingEntry(
                built="2022-01-02T00:00:00Z",
                distribution_version=1,
                url="http://example.com/archive2.tar.gz",
                distribution_checksum="sha256:abcdef1234567890abcdef1234567890",
                enclosed_checksum="xxhash64:abcdef1234567890",
            ),
        ]
        return ListingDocument(available={1: entries}, provider="test_provider")

    @pytest.fixture
    def built_document(self):
        subject = ListingDocument.new(provider="nvd")

        subject.add(
            ListingEntry(
                built=datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                distribution_version=3,
                url="https://b-place.com/something-1.tar.gz",
                distribution_checksum="sha256:123456789",
                enclosed_checksum="xxh64:123456789",
            )
        )

        subject.add(
            ListingEntry(
                built=datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                distribution_version=3,
                url="https://a-place.com/something.tar.gz",
                distribution_checksum="sha256:123456789",
                enclosed_checksum="xxh64:123456789",
            )
        )

        subject.add(
            ListingEntry(
                built=datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                distribution_version=3,
                url="https://c-place.com/something.tar.gz",
                distribution_checksum="sha256:123456789",
                enclosed_checksum="xxh64:123456789",
            )
        )

        subject.add(
            ListingEntry(
                built=datetime(2017, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                distribution_version=4,
                url="https://b-place.com/something-1.tar.zst",
                distribution_checksum="sha256:123456789",
                enclosed_checksum="xxh64:123456789",
            )
        )

        subject.add(
            ListingEntry(
                built=datetime(2016, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                distribution_version=4,
                url="https://a-place.com/something.tar.zst",
                distribution_checksum="sha256:123456789",
                enclosed_checksum="xxh64:123456789",
            )
        )

        subject.add(
            ListingEntry(
                built=datetime(2019, 11, 28, 23, 55, 59, 342380).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                distribution_version=4,
                url="https://c-place.com/something.tar.zst",
                distribution_checksum="sha256:123456789",
                enclosed_checksum="xxh64:123456789",
            )
        )

        return subject

    def test_latest_entry(self, document, built_document):
        latest_entry = document.latest_entry(1)
        assert latest_entry is not None
        assert latest_entry.distribution_version == 1
        assert latest_entry.url == "http://example.com/archive1.tar.gz"

        assert "https://c-place.com/something.tar.gz" == built_document.latest_entry(3).url
        assert "https://c-place.com/something.tar.zst" == built_document.latest_entry(4).url

    def test_latest_entry_no_entries(self, document):
        latest_entry = document.latest_entry(2)
        assert latest_entry is None

    def test_schema(self, built_document, validate_json_schema):
        content = json.dumps(built_document.to_dict())
        validate_json_schema(content)
