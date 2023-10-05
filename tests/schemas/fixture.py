import datetime

from typing import Optional

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.observables import ipv4, hostname, url
from core.schemas.entity import ThreatActor,Campaign
from core.schemas.tag import Tag
from core.schemas.indicator import Regex, DiamondModel
from core.schemas.template import Template
from core.schemas.task import ExportTask
from core.schemas.user import UserSensitive

import unittest


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()

    def test_something(self):
        user = UserSensitive(username="yeti", admin=True)
        user.set_password("yeti")
        user.save()

        user = UserSensitive(username="user", admin=False)
        user.set_password("user")
        user.save()

        ip_hacker = ipv4.IPv4(value="8.8.8.8").save()
        c2_hacker = hostname.Hostname(value="c2.hacker.com").save()
        www_hacker = hostname.Hostname(value="www.hacker.com").save()
        hacker = hostname.Hostname(value="hacker.com").save()
        hacker.link_to(www_hacker, "domain", "Domain")
        hacker.link_to(c2_hacker, "domain", "Domain")
        hacker.link_to(ip_hacker, "ip", "IP")
        hacker.tag(["hacker"])
        ta = ThreatActor(name="HackerActor", relevant_tags=["hacker_sus"]).save()
        ta.link_to(hacker, "c2", "C2 infrastructure")
        campaign = Campaign(name="HackerCampaign").save()
        campaign.link_to(ta, "actor", "Actor")
        campaign.relevant_tags = ["hacker_sus"]
        www_hacker.tag(["web", "hacker"])
        c2_hacker.tag(["web", "hacker"])
        sus_hacker = hostname.Hostname(value="sus.hacker.com").save()
        sus_hacker.tag(["web", "hacker", "hacker_sus"])
        regex = Regex(
            name="Hacker regex",
            pattern="^hacker.*",
            location="network",
            diamond=DiamondModel.capability,
        ).save()

        template = Template(name="RandomTemplate", template="<blah></blah>").save()
        export = ExportTask(
            name="RandomExport",
            template_name=template.name,
            include_tags=["include"],
            exclude_tags=["exclude"],
            ignore_tags=["ignore"],
            acts_on=["url"],
        ).save()
