import logging
from dateutil import parser
from dateutil.tz import gettz, UTC
from tldextract import TLDExtract
from core.config.config import yeti_config

tzinfos = {
    "CEST": gettz("Europe/Amsterdam"),
    "CST": gettz("Europe/Amsterdam")
}


tld_extract_dict = {
    'extra_suffixes': list(),
    'suffix_list_urls': None
}

if hasattr(yeti_config, "tldextract"):
    if yeti_config.tldextract.extra_suffixes:
        tld_extract_dict['extra_suffixes'] = yeti_config.tldextract.extra_suffixes.split(',')
    if yeti_config.tldextract.suffix_list_urls:
        tld_extract_dict['suffix_list_urls'] = yeti_config.tldextract.suffix_list_urls

def tldextract_parser(url):
    parts = None

    try:
        parts = TLDExtract(**tld_extract_dict)(url)
    except Exception as e:
        logging.error(e)

    return parts

def parse_date_to_utc(date):
    """
        parse date and convert it to UTC timezone
    """

    return parser.parse(date, tzinfos=tzinfos).astimezone(UTC)
