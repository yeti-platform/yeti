import datetime
import logging
import sys
import time
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import audit, dfiq, entity, indicator
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class TimelineLogTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def test_new_entity_makes_timeline_log(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        response = client.get(f"/api/v2/audit/timeline/entities/{data['id']}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data[0]), 1)
        self.assertEqual(data[0][0]["action"], "create")

    def test_entity_patch_makes_timeline_log(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        response = client.patch(
            f"/api/v2/entities/{data['id']}",
            json={
                "entity": {
                    "name": "ta2",
                    "type": "threat-actor",
                    "description": "new_description",
                }
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        response = client.get(f"/api/v2/audit/timeline/entities/{data['id']}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2)
        self.assertEqual(data[0][1]["action"], "update")
        self.assertEqual(data[0][1]["details"], {"description": "new_description"})

    def test_entity_tag_makes_timeline_log(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        entity_id = data["id"]

        response = client.post(
            "/api/v2/entities/tag", json={"ids": [entity_id], "tags": ["tag1"]}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [entity_id], "tags": ["tag2"], "strict": True},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.get(f"/api/v2/audit/timeline/entities/{entity_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 3, data)

        self.assertEqual(data[0][1]["action"], "tag", data)
        self.assertEqual(
            data[0][1]["details"], {"added": ["tag1"], "removed": []}, data
        )
        self.assertEqual(data[0][2]["action"], "tag", data)
        self.assertEqual(
            data[0][2]["details"], {"added": ["tag2"], "removed": ["tag1"]}, data
        )

    def test_new_indicator_makes_timeline_log(self):
        response = client.post(
            "/api/v2/indicators/",
            json={
                "indicator": {
                    "name": "ind1",
                    "type": "regex",
                    "pattern": "test",
                    "diamond": "adversary",
                }
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        indicator_id = data["id"]
        response = client.get(f"/api/v2/audit/timeline/indicators/{indicator_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 1)
        self.assertEqual(data[0][0]["action"], "create")

    def test_indicator_patch_makes_timeline_log(self):
        response = client.post(
            "/api/v2/indicators/",
            json={
                "indicator": {
                    "name": "ind1",
                    "type": "regex",
                    "pattern": "test",
                    "diamond": "adversary",
                }
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        response = client.patch(
            f"/api/v2/indicators/{data['id']}",
            json={
                "indicator": {
                    "name": "ind1",
                    "type": "regex",
                    "pattern": "test",
                    "diamond": "adversary",
                    "description": "new_description",
                }
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        response = client.get(f"/api/v2/audit/timeline/indicators/{data['id']}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2)
        self.assertEqual(data[0][1]["action"], "update")
        self.assertEqual(data[0][1]["details"], {"description": "new_description"})

    def test_tag_indicator_makes_timeline_log(self):
        response = client.post(
            "/api/v2/indicators/",
            json={
                "indicator": {
                    "name": "ind1",
                    "type": "regex",
                    "pattern": "test",
                    "diamond": "adversary",
                }
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        indocator_id = data["id"]

        response = client.post(
            "/api/v2/indicators/tag", json={"ids": [indocator_id], "tags": ["tag1"]}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.post(
            "/api/v2/indicators/tag",
            json={"ids": [indocator_id], "tags": ["tag2"], "strict": True},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.get(f"/api/v2/audit/timeline/indicators/{indocator_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 3, data)

        self.assertEqual(data[0][1]["action"], "tag", data)
        self.assertEqual(
            data[0][1]["details"], {"added": ["tag1"], "removed": []}, data
        )
        self.assertEqual(data[0][2]["action"], "tag", data)
        self.assertEqual(
            data[0][2]["details"], {"added": ["tag2"], "removed": ["tag1"]}, data
        )

    def test_new_observable_makes_timeline_log(self):
        response = client.post(
            "/api/v2/observables/",
            json={
                "type": "hostname",
                "value": "tomchop.me",
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        observable_id = data["id"]
        response = client.get(f"/api/v2/audit/timeline/observables/{observable_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 1)
        self.assertEqual(data[0][0]["action"], "create")

    def test_observable_context_makes_timeline_log(self):
        response = client.post(
            "/api/v2/observables/",
            json={
                "type": "hostname",
                "value": "tomchop.me",
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        observable_id = data["id"]

        response = client.post(
            f"/api/v2/observables/{observable_id}/context",
            json={"source": "test", "context": {"test": "test"}},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.get(f"/api/v2/audit/timeline/observables/{observable_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2, data)
        self.assertEqual(data[0][1]["action"], "update", data)
        self.assertEqual(
            data[0][1]["details"],
            {"context": [{"test": "test", "source": "test"}]},
            data,
        )

    def test_observable_from_text_makes_timeline_log(self):
        response = client.post(
            "/api/v2/observables/import/text",
            json={"text": "tomchop.me\ngoogle.com"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        observable_id = data["added"][0]["id"]
        response = client.get(f"/api/v2/audit/timeline/observables/{observable_id}")
        timeline_data = response.json()
        self.assertEqual(response.status_code, 200, timeline_data)
        self.assertEqual(len(timeline_data[0]), 1)
        last_entry = timeline_data[0][0]
        self.assertEqual(last_entry["action"], "import-text")
        self.assertEqual(last_entry["details"]["value"], "tomchop.me")

        observable_id = data["added"][1]["id"]
        response = client.get(f"/api/v2/audit/timeline/observables/{observable_id}")
        timeline_data = response.json()
        self.assertEqual(response.status_code, 200, timeline_data)
        self.assertEqual(len(timeline_data[0]), 1)
        last_entry = timeline_data[0][0]
        self.assertEqual(last_entry["action"], "import-text")
        self.assertEqual(last_entry["details"]["value"], "google.com")

    def test_observable_tag_makes_timeline_log(self):
        response = client.post(
            "/api/v2/observables/",
            json={
                "type": "hostname",
                "value": "tomchop.me",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        observable_id = data["id"]

        response = client.post(
            "/api/v2/observables/tag", json={"ids": [observable_id], "tags": ["tag1"]}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.post(
            "/api/v2/observables/tag",
            json={"ids": [observable_id], "tags": ["tag2"], "strict": True},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.get(f"/api/v2/audit/timeline/observables/{observable_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 3, data)

        self.assertEqual(data[0][1]["action"], "tag", data)
        self.assertEqual(
            data[0][1]["details"], {"added": ["tag1"], "removed": []}, data
        )
        self.assertEqual(data[0][2]["action"], "tag", data)
        self.assertEqual(
            data[0][2]["details"], {"added": ["tag2"], "removed": ["tag1"]}, data
        )

    def test_new_dfiq_makes_timeline_log(self):
        dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            uuid="fake_facet_uuid",
            dfiq_version="1.1.0",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
        ).save()

        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": "question",
                "update_indicators": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        dfiq_id = data["id"]
        response = client.get(f"/api/v2/audit/timeline/dfiq/{dfiq_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 1)
        self.assertEqual(data[0][0]["action"], "create")

        indicators = list(indicator.Indicator.list())

        response = client.get(f"/api/v2/audit/timeline/indicators/{indicators[0].id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 1)
        self.assertEqual(data[0][0]["actor"], "test")
        self.assertEqual(data[0][0]["action"], "create")

    def test_delete_observable_makes_timeline_log(self):
        response = client.post(
            "/api/v2/observables/",
            json={
                "type": "hostname",
                "value": "tomchop.me",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        observable_id = data["id"]

        response = client.delete(f"/api/v2/observables/{observable_id}")
        self.assertEqual(response.status_code, 200)
        response = client.get(f"/api/v2/audit/timeline/observables/{observable_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2, data)
        self.assertEqual(data[0][1]["action"], "delete", data)

    def test_delete_entity_makes_timeline_log(self):
        response = client.post(
            "/api/v2/entities/",
            json={"entity": {"name": "ta2", "type": "threat-actor"}},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        entity_id = data["id"]

        response = client.delete(f"/api/v2/entities/{entity_id}")
        self.assertEqual(response.status_code, 200)
        response = client.get(f"/api/v2/audit/timeline/entities/{entity_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2, data)
        self.assertEqual(data[0][1]["action"], "delete", data)

    def test_delete_indicator_makes_timeline_log(self):
        response = client.post(
            "/api/v2/indicators/",
            json={
                "indicator": {
                    "name": "ind1",
                    "type": "regex",
                    "pattern": "test",
                    "diamond": "adversary",
                }
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        indicator_id = data["id"]

        response = client.delete(f"/api/v2/indicators/{indicator_id}")
        self.assertEqual(response.status_code, 200)
        response = client.get(f"/api/v2/audit/timeline/indicators/{indicator_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2, data)
        self.assertEqual(data[0][1]["action"], "delete", data)

    def test_delete_dfiq_makes_timeline_log(self):
        dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            uuid="fake_scenario_uuid",
            dfiq_version="1.1.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        with open("tests/dfiq_test_data/F1005.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": "facet",
            },
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        facet_id = data["id"]

        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": "question",
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        question_id = data["id"]

        response = client.delete(f"/api/v2/dfiq/{facet_id}")
        self.assertEqual(response.status_code, 200)

        response = client.get(f"/api/v2/audit/timeline/dfiq/{facet_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2, data)
        self.assertEqual(data[0][1]["action"], "delete", data)

        response = client.get(f"/api/v2/audit/timeline/dfiq/{question_id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data[0]), 2, data)
        self.assertEqual(data[0][1]["action"], "delete-parent", data)
        self.assertEqual(data[0][1]["details"], {"parent": facet_id})
