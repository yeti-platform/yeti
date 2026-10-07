# DEPRECATED
import logging
from typing import Any

from dateutil import parser
from dateutil.tz import UTC, gettz
from tldextract import TLDExtract  # ty: ignore[unresolved-import]

from core.config.config import yeti_config

tzinfos = {"CEST": gettz("Europe/Amsterdam"), "CST": gettz("Europe/Amsterdam")}


tld_extract_dict: dict[str, Any] = {"extra_suffixes": list(), "suffix_list_urls": None}

_extra_suffixes = yeti_config.get("tldextract", "extra_suffixes", None)
if _extra_suffixes:
    tld_extract_dict["extra_suffixes"] = _extra_suffixes.split(",")
_suffix_list_urls = yeti_config.get("tldextract", "suffix_list_urls", None)
if _suffix_list_urls:
    tld_extract_dict["suffix_list_urls"] = _suffix_list_urls


def tldextract_parser(url):
    parts = None

    try:
        parts = TLDExtract(**tld_extract_dict)(url)
    except Exception as e:
        logging.error(e)

    return parts


def parse_date_to_utc(date):
    """Parses a string to a datetime object in UTC timezone.

    Args:
      date (str): string-timestamp to convert to datetime object.
          e.g. 2019-06-09 00:00:00

    Returns:
      A datetime.datetime object in UTC timezone.
    """

    return parser.parse(date, tzinfos=tzinfos).astimezone(UTC)
