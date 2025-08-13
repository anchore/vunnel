import logging

from dateutil.parser import parse as dateutil_parse


def normalize_date(date_str: str) -> str | None:
    try:
        parsed_date = dateutil_parse(date_str)
        return parsed_date.strftime("%Y-%m-%d")
    except ValueError as e:
        logging.error(f"failed to parse fix date '{date_str}': {e}")
    return None
