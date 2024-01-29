import unittest

from core import database_arango
from core.schemas.entity import Investigation, Malware, ThreatActor
from core.schemas.indicator import DiamondModel, Query, QueryType, Regex
from core.schemas.observables import (
    bic,
    generic_observable,
    hostname,
    iban,
    ipv4,
    mac_address,
)
from core.schemas.task import ExportTask
from core.schemas.template import Template
from core.schemas.user import UserSensitive


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
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
        for i in range(100):
            ip = ipv4.IPv4(value=f"8.8.8.{i}").save()
            ip.link_to(c2_hacker, "resolves", "resolves")
        c2_hacker.link_to(ip_hacker, "pdns", "pdns")
        www_hacker = hostname.Hostname(value="www.hacker.com").save()
        hacker = hostname.Hostname(value="hacker.com").save()
        sus_hacker = hostname.Hostname(value="sus.hacker.com").save()
        mac_address.MacAddress(value="00:11:22:33:44:55").save()
        generic = generic_observable.GenericObservable(
            value="SomeInterestingString"
        ).save()
        generic.add_context("test_source", {"test": "test"})

        hacker.link_to(www_hacker, "domain", "Domain")
        hacker.link_to(c2_hacker, "domain", "Domain")
        hacker.link_to(ip_hacker, "ip", "IP")

        c2_hacker.tag(["hacker", "web", "xmrig"])
        hacker.tag(["hacker"])
        www_hacker.tag(["web", "hacker", "xmrig"])
        sus_hacker.tag(["web", "hacker", "hacker_sus"])

        ibantest = iban.IBAN(value="GB33BUKB20201555555555").save()
        bictest = bic.BIC(value="BUKBGB22XXX").save()
        ibantest.link_to(bictest, "bic", "BIC")
        ibantest.tag(["example"])

        ta = ThreatActor(name="HackerActor").save()
        ta.tag(["Hack!ré T@ëst"])
        ta.link_to(hacker, "uses", "Uses domain")

        regex = Regex(
            name="hex",
            pattern="/tmp/[0-9a-f]",
            location="bodyfile",
            diamond=DiamondModel.capability,
        ).save()
        regex.link_to(hacker, "indicates", "Domain dropped by this regex")
        xmrig = Malware(name="xmrig").save()
        xmrig.tag(["xmrig"])
        regex.link_to(xmrig, "indicates", "Usual name for dropped binary")

        Query(
            name="ssh succesful logins",
            location="syslogs",
            diamond=DiamondModel.capability,
            pattern='(reporter:"sshd" AND Accepted)',
            query_type=QueryType.opensearch,
            target_systems=["timesketch", "plaso"],
            relevant_tags=["ssh", "login"],
        ).save()
        i = Investigation(
            name="coin mining case",
            reference="http://timesketch-server/sketch/12345",
            relevant_tags=["coin", "mining"],
        ).save()
        template = Template(name="RandomTemplate", template="<blah></blah>").save()
        ExportTask(
            name="RandomExport",
            template_name=template.name,
            include_tags=["include"],
            exclude_tags=["exclude"],
            ignore_tags=["ignore"],
            acts_on=["url"],
        ).save()
