from __future__ import annotations

import gzip
import logging
import os
from io import BytesIO
from typing import TYPE_CHECKING

import requests

from vunnel import utils, workspace

if TYPE_CHECKING:
    from collections.abc import Generator


NAMESPACE = "epss"


class Manager:
    _csv_url_template_ = "https://epss.cyentia.com/epss_scores-{}.csv.gz"
    _csv_file_ = "epss_data.csv"

    def __init__(
        self,
        dataset: str,
        ws: workspace.Workspace,
        url_template: str = "",
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.workspace = ws
        self.download_timeout = download_timeout

        if url_template:
            self._csv_url_template_ = url_template

        self._csv_url_ = self._csv_url_template_.format(dataset)

        self.urls = [self._csv_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self) -> Generator[tuple[str | None, dict[str, str | float]], None, None]:
        filepath = self._download()
        yield from self._normalize(filepath)

    @utils.retry_with_backoff()
    def _download(self) -> str:
        csv_file_path = os.path.join(self.workspace.input_path, self._csv_file_)

        self.logger.info(f"downloading vulnerability data from {self._csv_url_}")

        r = requests.get(self._csv_url_, timeout=self.download_timeout)
        r.raise_for_status()

        with gzip.GzipFile(fileobj=BytesIO(r.content), mode="rb") as gzfh, open(csv_file_path, "wb") as fh:
            fh.write(gzfh.read())

        return csv_file_path

    def _normalize(self, filepath: str) -> Generator[tuple[str, dict[str, str | float]], None, None]:
        fields: list[str] = []
        date: str | None = None

        self.logger.info(f"processing {_count_lines(filepath)} EPSS records")

        with open(filepath, encoding="utf-8") as file_handle:
            for line in file_handle:
                line = line.strip()
                if not line:
                    continue

                if date is None:
                    extracted_date = _extract_date_from_comment(line)
                    if extracted_date:
                        date = extracted_date
                        continue

                if not fields:
                    fields = _parse_header_fields(line)
                    continue

                if not date:
                    raise ValueError("couldn't find date at the top of the CSV file")

                if not line.startswith("CVE-"):
                    continue

                record = _parse_record(line, fields, date)
                if record:
                    cve: str | None = record.get("cve")  # type: ignore[assignment]
                    if not cve:
                        logging.warning(f"skipping record without a CVE: {record}")
                        continue
                    yield cve, record


def _extract_date_from_comment(line: str) -> str | None:
    if not (line.startswith("#") and "score_date" in line):
        return None

    for field in line.split(","):
        if field.startswith("score_date"):
            return field.split(":")[1].split("T")[0]
    return None


def _parse_header_fields(line: str) -> list[str]:
    if line.startswith("CVE-"):
        return []

    fields = [f.lower() for f in line.split(",")]
    if "cve" not in fields:
        raise ValueError("couldn't find 'cve' field in the CSV file header")
    return fields


def _parse_record(line: str, fields: list[str], date: str) -> dict[str, str | float] | None:
    tokens = line.split(",")
    if len(tokens) != len(fields):
        return None

    try:
        input_record = {}
        for i, field in enumerate(fields):
            value = tokens[i]
            input_record[field] = value if field.lower() == "cve" else float(value)
        input_record["date"] = date
        return input_record
    except Exception:
        return None


def _count_lines(filepath: str) -> int:
    with open(filepath) as f:
        return sum(1 for _ in f)
