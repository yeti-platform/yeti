from __future__ import unicode_literals
import logging
import os

from core.analytics import InlineAnalytics
from core.errors import ObservableValidationError
import geoip2.database
from geoip2.errors import AddressNotFoundError


try:
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "GeoLite2-City.mmdb")
    reader = geoip2.database.Reader(path)
except IOError as e:
    logging.info(
        "Could not open GeoLite2-City.mmdb. Will proceed without GeoIP data")
    logging.info(e)
    reader = False


class ProcessIp(InlineAnalytics):

    default_values = {
        "name": "ProcessIp",
        "description": "Extracts information from IP addresses",
    }

    ACTS_ON = 'Ip'

    @staticmethod
    def each(ip):
        try:
            if reader:
                response = reader.city(ip.value)
                ip.geoip = {
                    "country": response.country.iso_code,
                    "city": response.city.name
                }
                ip.save()
        except ObservableValidationError:
            logging.error("An error occurred when trying to add {} to the database".format(ip.value))
        except AddressNotFoundError:
            logging.error("{} was not found in the GeoIp database".format(ip.value))
