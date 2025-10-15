from __future__ import annotations

from datetime import datetime
from pathlib import Path

from django.test import SimpleTestCase
from django.urls import reverse

from chat_extractor.forms import ParsedFilters
from chat_extractor.services.extractor import ExtractionService

TEST_DATA_DIR = Path(__file__).resolve().parent / "data"


def build_filters(**overrides):
    defaults = dict(
        base_dir=TEST_DATA_DIR,
        contacts=[],
        limit=5,
        start_time=None,
        end_time=None,
        message_types=[],
        include_subdirectories=False,
    )
    defaults.update(overrides)
    return ParsedFilters(**defaults)


class ExtractionServiceTests(SimpleTestCase):
    def setUp(self) -> None:
        self.service = ExtractionService()

    def test_extract_without_filters_returns_messages(self) -> None:
        result = self.service.extract(build_filters())
        self.assertGreaterEqual(result.stats.total_messages, 3)
        self.assertEqual(result.stats.matched_messages, len(result.messages))
        self.assertTrue(result.grouped_threads)

    def test_extract_with_contact_filter(self) -> None:
        filters = build_filters(contacts=["Zhang San"], limit=10)
        result = self.service.extract(filters)
        self.assertTrue(all("zhang san" in message.talker.lower() for message in result.messages))
        self.assertTrue(all("zhang san" in group.name.lower() for group in result.grouped_threads))

    def test_extract_respects_time_range(self) -> None:
        filters = build_filters(
            start_time=datetime(2024, 3, 2, 0, 0),
            end_time=datetime(2024, 3, 2, 23, 59),
            limit=10,
        )
        result = self.service.extract(filters)
        for message in result.messages:
            if message.timestamp:
                naive = message.timestamp.replace(tzinfo=None)
                self.assertGreaterEqual(naive, datetime(2024, 3, 2, 0, 0))
                self.assertLessEqual(naive, datetime(2024, 3, 2, 23, 59))

    def test_top_contacts_are_sorted(self) -> None:
        result = self.service.extract(build_filters(limit=50))
        contacts = result.stats.top_contacts
        self.assertTrue(contacts)
        counts = [item["count"] for item in contacts]
        self.assertEqual(counts, sorted(counts, reverse=True))


class ExportViewTests(SimpleTestCase):
    def test_export_returns_plain_text(self) -> None:
        response = self.client.post(
            reverse("chat_extractor:export"),
            data={
                "base_dir": str(TEST_DATA_DIR),
                "limit": "5",
                "include_subdirectories": "on",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        self.assertIn("微信聊天记录导出", response.content.decode("utf-8"))
