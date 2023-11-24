from datetime import timedelta

import pandas as pd
from core.config.config import yeti_config
from core.entities import Company
from core.feed import Feed
from core.observables import Hostname, Ip
from pypdns import api


class PassiveDNS(Feed):
    default_values = {
        "frequency": timedelta(days=1),
        "name": "PassiveDNS",
        "source": "https://github.com/PassiveDNS/PassiveDNS",
        "description": "Alerts of monotoring DNS supported by PassiveDNS",
    }

    def update(self):
        login = yeti_config.get("passivedns", "login")
        password = yeti_config.get("passivedns", "password")
        url = yeti_config.get("passivedns", "url")
        pdns = api.Api_PDNS(url)
        pdns.connect(login, password)

        r = pdns.get_alerts(limit=100)

        df = pd.DataFrame(r["data"])
        df.columns = r["columns"]

        for index, line in df.iterrows():
            self.analyze(line, pdns)

    def analyze(self, item, pdns):
        context_domain = dict(source=self.name)
        context_ip = dict(source=self.name)

        domain_name = Hostname.get_or_create(value=item["Domain name"])
        ip = Ip.get_or_create(value=item["Current IP address"])
        infos_ip = pdns.get_reverse(item["Current IP address"])
        infos_domain = pdns.get_records(item["Domain name"])

        infos = list(
            filter(
                lambda x: x["domain_name"] == item["Domain name"],
                infos_ip["resolution_list"],
            )
        )[0]

        company = Company.get_or_create(
            name=infos_domain["ip"]["location"]["organization"]
        )
        context_ip["ISP"] = infos_domain["ip"]["location"]["ISP"]
        context_ip["country"] = infos_domain["ip"]["location"]["country"]
        context_ip["last_updated"] = infos["last_updated_at"]
        context_ip["first_updated"] = infos["first_updated_at"]

        ip.active_link_to(company, "company", self.name)

        domain_name.active_link_to(ip, "ip", self.name, clean_old=False)

        context_domain["last updated"] = "{} : {}".format(
            ip.value,
            infos["last_updated_at"],
        )

        ns_servers = filter(lambda x: x["type"] == "NS", infos_domain["dn"]["records"])
        for name_server in ns_servers:
            ns_serv = Hostname.get_or_create(value=name_server["target"])
            ns_serv.active_link_to(domain_name, "NS", self.name, clean_old=False)

        ip.add_context(context_ip)

        if item["Domain name tags"]:
            domain_name.tag(item["Domain name tags"])

        domain_name.add_context(context_domain)
