from pprint import pformat
from ipwhois import IPWhois
from core.analytics import OneShotAnalytics
from core.entities import Company
from core.observables import Email


class NetworkWhois(OneShotAnalytics):

    default_values = {
        "name": "NetworkWhois",
        "description": "Perform a Network Whois request on the IP address and tries to"
        " extract relevant information.",
    }

    ACTS_ON = "Ip"

    @staticmethod
    def analyze(ip, results):
        links = set()

        r = IPWhois(ip.value)
        result = r.lookup_whois()
        results.update(raw=pformat(result))

        # Let's focus on the most specific information
        # Which should be in the smallest subnet
        n = 0
        smallest_subnet = None

        for network in result["nets"]:
            cidr_bits = int(network["cidr"].split("/")[1].split(",")[0])
            if cidr_bits > n:
                n = cidr_bits
                smallest_subnet = network

        if smallest_subnet:
            # Create the company
            company = Company.get_or_create(
                name=smallest_subnet["description"].split("\n")[0]
            )
            links.update(ip.active_link_to(company, "hosting", "Network Whois"))

            # Link it to every email address referenced
            if smallest_subnet["emails"]:
                for email_address in smallest_subnet["emails"]:
                    email = Email.get_or_create(value=email_address)
                    links.update(company.link_to(email, None, "Network Whois"))

            # Copy the subnet info into the main dict
            for key in smallest_subnet:
                if smallest_subnet[key]:
                    result["net_{}".format(key)] = smallest_subnet[key]

        # Add the network whois to the context if not already present
        for context in ip.context:
            if context["source"] == "network_whois":
                break
        else:
            # Remove the nets info (the main one was copied)
            result.pop("nets", None)
            result.pop("raw", None)
            result.pop("raw_referral", None)
            result.pop("referral", None)
            result.pop("query", None)

            result["source"] = "network_whois"
            ip.add_context(result)

        return list(links)
