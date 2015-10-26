import logging

from core.analytics import OneShotAnalytics


class QueryVirusTotal(OneShotAnalytics):

    settings = {
        "name": "QueryVirusTotal",
        "description": "Queries VT for a single hash, adding context to the element "
                       "and linking to other elements"
    }

    ACTS_ON = ["Hash"]

    @staticmethod
    def analyze(hash):
        logging.warning("Querying hash {} on VT".format(hash))
