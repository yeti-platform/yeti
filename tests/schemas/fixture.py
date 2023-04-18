import datetime

from typing import Optional

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.entity import ThreatActor
from core.schemas.tag import Tag

import unittest

class TagTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        ip_google = Observable(value="8.8.8.8", type="ip").save()
        c2_google = Observable(value="c2.google.com", type="hostname").save()
        www_google = Observable(value="www.google.com", type="hostname").save()
        google = Observable(value="google.com", type="hostname").save()
        google.link_to(www_google, 'domain', 'Domain')
        google.link_to(c2_google, 'domain', 'Domain')
        google.link_to(ip_google, 'ip', 'IP')
        ta = ThreatActor(name="GoogleActor", relevant_tags=["google_sus"]).save()
        ta.link_to(google, 'c2', 'C2 infrastructure')
        www_google.tag(['web', 'google'])
        c2_google.tag(['web', 'google'])
        sus_google = Observable(value="sus.google.com", type="hostname").save()
        sus_google.tag(['web', 'google', 'google_sus'])


    def test_something(self):
        self.assertEqual(1, 1)
