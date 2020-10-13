from __future__ import unicode_literals
import logging

import geoip2.database
from geoip2.errors import AddressNotFoundError

from core.analytics import InlineAnalytics
from core.config.config import yeti_config
from core.errors import ObservableValidationError

reader = None
try:
    path = yeti_config.get("maxmind", "path")
    if path:
        reader = geoip2.database.Reader(path)
except IOError as e:
    logging.info("Could not open GeoLite2-City.mmdb. Will proceed without GeoIP data")
    logging.info(e)
    reader = False


class ProcessIp(InlineAnalytics):

    default_values = {
        "name": "ProcessIp",
        "description": "Extracts information from IP addresses",
    }

    ACTS_ON = "Ip"

    @staticmethod
    def each(ip):
        try:
            if reader:
                response = reader.city(ip.value)
                ip.geoip = {
                    "country": response.country.iso_code,
                    "city": response.city.name,
                }
                ip.save()
        except ObservableValidationError:
            logging.error(
                "An error occurred when trying to add {} to the database".format(
                    ip.value
                )
            )
        except AddressNotFoundError:
            logging.error("{} was not found in the GeoIp database".format(ip.value))
