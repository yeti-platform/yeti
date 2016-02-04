import logging

from core.analytics import OneShotAnalytics


class QueryVirusTotal(OneShotAnalytics):

    default_values = {
        "name": "QueryVirusTotal",
        "description": "Queries VT for a single hash, adding context to the observable "
                       "and linking to other observables"
    }

    ACTS_ON = "Hash"

    @staticmethod
    def analyze(hash, settings={}):
        logging.warning("Querying hash {} on VT".format(hash))
        return []
