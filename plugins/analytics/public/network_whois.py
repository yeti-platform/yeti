from core.schemas import task
from core import taskmanager
from core.schemas.observable import ObservableType
from core.schemas.observables import ipv4, email
from core.schemas.entity import Company
from ipwhois import IPWhois


class NetworkWhois(task.AnalyticsTask):
    _defaults = {
        "name": "NetworkWhois",
        "description": "Perform a Network Whois request on the IP address and tries to"
        " extract relevant information.",
    }

    acts_on: list[ObservableType] = [ObservableType.ip]

    def each(self, ip: ipv4.IPv4):

        r = IPWhois(ip.value)
        result = r.lookup_whois()

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
            company = Company(name=smallest_subnet["description"].split("\n")[0])

            # Link it to every email address referenced
            if smallest_subnet["emails"]:
                for email_address in smallest_subnet["emails"]:
                    email_obs = email.Email(value=email_address)
                    company.link_to(email_obs, "email-company", "IPWhois")

            # Copy the subnet info into the main dict
            for key in smallest_subnet:
                if smallest_subnet[key]:
                    result["net_{}".format(key)] = smallest_subnet[key]

            ip.add_context("IPWhois", result)


taskmanager.TaskManager.register_task(NetworkWhois)
