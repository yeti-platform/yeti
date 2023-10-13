import unittest

from core import database_arango
from core.schemas.entity import Investigation, Malware, ThreatActor
from core.schemas.indicator import DiamondModel, Query, QueryType, Regex
from core.schemas.observables import hostname, ipv4
from core.schemas.task import ExportTask
from core.schemas.template import Template
from core.schemas.user import UserSensitive


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
        sus_hacker = hostname.Hostname(value="sus.hacker.com").save()

        hacker.link_to(www_hacker, "domain", "Domain")
        hacker.link_to(c2_hacker, "domain", "Domain")
        hacker.link_to(ip_hacker, "ip", "IP")

        c2_hacker.tag(["hacker", "web"])
        hacker.tag(["hacker"])
        www_hacker.tag(["web", "hacker"])
        sus_hacker.tag(["web", "hacker", "hacker_sus"])

        ta = ThreatActor(name="HackerActor").save()
        ta.tag(["Hack!ré T@ëst"])
        ta.link_to(hacker, "c2", "C2 infrastructure")

        regex = Regex(
            name="hex",
            pattern="/tmp/[0-9a-f]",
            location="bodyfile",
            diamond=DiamondModel.capability,
        ).save()
        mal = Malware(name='xmrig').save()
        mal.link_to(regex, "indicates", "Usual name for dropped binary")

        q = Query(
            name="ssh succesful logins",
            location="syslogs",
            diamond=DiamondModel.capability,
            pattern='(reporter:"sshd" AND Accepted)',
            query_type=QueryType.opensearch,
            target_systems=['timesketch', 'plaso'],
            relevant_tags=['ssh', 'login']).save()
        i = Investigation(
            name='coin mining case',
            reference='http://timesketch-server/sketch/12345',
            relevant_tags=['coin', 'mining']).save()
        template = Template(name="RandomTemplate", template="<blah></blah>").save()
        export = ExportTask(
            name="RandomExport",
            template_name=template.name,
            include_tags=["include"],
            exclude_tags=["exclude"],
            ignore_tags=["ignore"],
            acts_on=["url"],
        ).save()
