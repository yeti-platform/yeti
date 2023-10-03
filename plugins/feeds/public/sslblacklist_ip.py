from io import StringIO
from datetime import timedelta
from typing import ClassVar

import pandas as pd

from core.schemas.observables import ipv4, url
from core.schemas import task
from core import taskmanager


class SSLBlackListIP(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "SSLBlackListIP",
        "description": "SSL Black List IP",
    }

    _SOURCE:ClassVar['str'] = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

    def run(self):
        response = self._make_request(self._SOURCE)
        if response:
            data = response.text
            names = names = ["Firstseen", "DstIP", "DstPort"]
            df = pd.read_csv(
                StringIO(data),
                comment="#",
                delimiter=",",
                names=names,
                quotechar='"',
                quoting=True,
                skipinitialspace=True,
                parse_dates=["Firstseen"],
                header=8,
            )
            df.fillna("", inplace=True)
            df = self._filter_observables_by_time(df, "Firstseen")

            for _, line in df.iterrows():
                self.analyze(line)

    def analyze(self, line):
        first_seen = line["Firstseen"]
        dst_ip = line["DstIP"]
        ip_obs = False
        tags = ["potentially_malicious_infrastructure", "c2"]
        port = line["DstPort"]
        context = {}
        context["first_seen"] = first_seen

        ip_obs = ipv4.IPv4(value=dst_ip).save()
        ip_obs.add_context(self.name, context)
        ip_obs.tag(tags)
        _url = "https://{dst_ip}:{port}/".format(dst_ip=dst_ip, port=port)

        url_obs = url.Url(value=_url).save()
        url_obs.add_context(self.name, context)
        url_obs.tag(tags)

        ip_obs.link_to(url_obs, "ip-url", self.name)


taskmanager.TaskManager.register_task(SSLBlackListIP)
