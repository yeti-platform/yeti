from __future__ import unicode_literals

import json
from datetime import datetime

from maclookup import ApiClient, exceptions as maclookup_exceptions
from core import taskmanager
from core.schemas import task
from core.schemas.observable import ObservableType
from core.schemas.observables.mac_address import MacAddress
from core.schemas.entity import Company
from core.config.config import yeti_config


class MacAddressIoApi(object):
    __MODULE_GROUP__ = "MacAddress.io"

    @staticmethod
    def get(mac_address):
        api_client = ApiClient(yeti_config.get("macaddressio", "api_key"))

        try:
            response = api_client.get_raw_data(mac_address, "json")
            return json.loads(response)

        except maclookup_exceptions.EmptyResponseException:
            raise LookupError("Empty response")

        except maclookup_exceptions.UnparsableResponseException:
            raise LookupError("Unparsable response")

        except maclookup_exceptions.ServerErrorException:
            raise LookupError("Internal server error")

        except maclookup_exceptions.UnknownOutputFormatException:
            raise LookupError("Unknown output")

        except maclookup_exceptions.AuthorizationRequiredException:
            raise LookupError("Authorization required")

        except maclookup_exceptions.AccessDeniedException:
            raise LookupError("Access denied")

        except maclookup_exceptions.InvalidMacOrOuiException:
            raise LookupError("Invalid MAC or OUI")

        except maclookup_exceptions.NotEnoughCreditsException:
            raise LookupError("Not enough credits")

        except Exception:
            raise LookupError("Unknown error")


class MacAddressIo(task.AnalyticsTask, MacAddressIoApi):
    _defaults = {
        "group": MacAddressIoApi.__MODULE_GROUP__,
        "name": "MacAddress Vendor lookup (macaddress.io)",
        "description": "Retrieve vendor details and other information regarding a given MAC address or an OUI from macaddress.io.",
    }

    acts_on: list[ObservableType] = [ObservableType.mac_address]

    def each(self, mac_address: MacAddress):
        lookup_results = MacAddressIoApi.get(mac_address.value)

        vendor = None
        try:
            if lookup_results["vendorDetails"]["companyName"] != "":
                vendor = Company(
                    name=lookup_results["vendorDetails"]["companyName"]
                ).save()
        except KeyError:
            return

        MacAddressIo.add_context_to_observable(mac_address, lookup_results)
        if vendor:
            mac_address.link_to(vendor, "Vendor", "MacAdress.io")

    @staticmethod
    def add_context_to_observable(mac_address: MacAddress, lookup_results: dict):
        context = dict(
            [
                ("raw", json.dumps(lookup_results, indent=2)),
                ("source", "MAC address vendor lookup (macaddress.io)"),
                # Mac address details
                ("Valid MAC address", lookup_results["macAddressDetails"]["isValid"]),
                (
                    "Transmission type",
                    lookup_results["macAddressDetails"]["transmissionType"],
                ),
                (
                    "Administration type",
                    lookup_results["macAddressDetails"]["administrationType"],
                ),
                # Vendor details
                ("OUI", lookup_results["vendorDetails"]["oui"]),
                (
                    "Vendor details are hidden",
                    lookup_results["vendorDetails"]["isPrivate"],
                ),
                ("Company name", lookup_results["vendorDetails"]["companyName"]),
                (
                    "Company's address",
                    lookup_results["vendorDetails"]["companyAddress"],
                ),
                ("Country code", lookup_results["vendorDetails"]["countryCode"]),
                # Block details
                ("Block found", lookup_results["blockDetails"]["blockFound"]),
                (
                    "The left border of the range",
                    lookup_results["blockDetails"]["borderLeft"],
                ),
                (
                    "The right border of the range",
                    lookup_results["blockDetails"]["borderRight"],
                ),
                (
                    "The total number of MAC addresses in this range",
                    lookup_results["blockDetails"]["blockSize"],
                ),
                (
                    "Assignment block size",
                    lookup_results["blockDetails"]["assignmentBlockSize"],
                ),
            ]
        )

        if lookup_results["blockDetails"]["dateCreated"]:
            context["Date when the range was allocated"] = datetime.strptime(
                lookup_results["blockDetails"]["dateCreated"], "%Y-%m-%d"
            ).strftime("%d %B %Y")

        if lookup_results["blockDetails"]["dateUpdated"]:
            context["Date when the range was last updated"] = datetime.strptime(
                lookup_results["blockDetails"]["dateUpdated"], "%Y-%m-%d"
            ).strftime("%d %B %Y")

        context = {k: v for k, v in context.items() if v}

        mac_address.add_context("MacAdress.io", context)


taskmanager.TaskManager.register_task(MacAddressIo)
