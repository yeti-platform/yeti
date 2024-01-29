import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import dfiq
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class DFIQTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def test_new_dfiq_scenario(self) -> None:
        with open("tests/dfiq_test_data/S1003.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.scenario,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data["id"])
        self.assertIsNotNone(data["created"])
        self.assertEqual(data["name"], "scenario1")
        self.assertEqual(data["dfiq_id"], "S1003")
        self.assertEqual(data["dfiq_version"], "1.0.0")
        self.assertEqual(data["description"], "Long description 1\n")
        self.assertEqual(data["type"], dfiq.DFIQType.scenario)
        self.assertEqual(data["dfiq_tags"], ["Tag1", "Tag2", "Tag3"])

    def test_new_dfiq_facet(self) -> None:
        scenario = dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
        ).save()

        with open("tests/dfiq_test_data/F1005.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.facet,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data["id"])
        self.assertIsNotNone(data["created"])
        self.assertEqual(data["name"], "facet1")
        self.assertEqual(data["dfiq_id"], "F1005")
        self.assertEqual(data["dfiq_version"], "1.0.0")
        self.assertEqual(data["description"], "Long description of facet1\n")
        self.assertEqual(data["type"], dfiq.DFIQType.facet)
        self.assertEqual(data["dfiq_tags"], ["Web Browser"])
        self.assertEqual(data["parent_ids"], ["S1003"])

        vertices, edges, total = scenario.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[f'dfiq/{data["id"]}'].dfiq_id, "F1005")
        self.assertEqual(edges[0][0].type, "facet")
        self.assertEqual(edges[0][0].description, "Uses DFIQ facet")
        self.assertEqual(total, 1)

    def test_new_dfiq_question(self) -> None:
        facet = dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["S1003"],
        ).save()

        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.question,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data["id"])
        self.assertIsNotNone(data["created"])
        self.assertEqual(data["name"], "What is a question?")
        self.assertEqual(data["dfiq_id"], "Q1020")
        self.assertEqual(data["dfiq_version"], "1.0.0")
        self.assertEqual(data["description"], None)
        self.assertEqual(data["type"], dfiq.DFIQType.question)
        self.assertEqual(data["dfiq_tags"], ["Web Browser"])
        self.assertEqual(data["parent_ids"], ["F1005"])

        vertices, edges, total = facet.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[f'dfiq/{data["id"]}'].dfiq_id, "Q1020")
        self.assertEqual(edges[0][0].type, "question")
        self.assertEqual(edges[0][0].description, "Uses DFIQ question")
        self.assertEqual(total, 1)

    def test_new_dfiq_approach(self) -> None:
        question = dfiq.DFIQQuestion(
            name="mock_question",
            dfiq_id="Q1020",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
        ).save()

        with open("tests/dfiq_test_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.approach,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data["id"])
        self.assertIsNotNone(data["created"])
        self.assertEqual(data["name"], "Approach1")
        self.assertEqual(data["dfiq_id"], "Q1020.10")
        self.assertEqual(data["dfiq_version"], "1.0.0")
        self.assertEqual(data["description"]["summary"], "Description for approach")
        self.assertEqual(data["type"], dfiq.DFIQType.approach)
        self.assertEqual(data["dfiq_tags"], ["Lots", "Of", "Tags"])

        vertices, edges, total = question.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[f'dfiq/{data["id"]}'].dfiq_id, "Q1020.10")
        self.assertEqual(edges[0][0].type, "approach")
        self.assertEqual(edges[0][0].description, "Uses DFIQ approach")
        self.assertEqual(total, 1)

    def test_dfiq_patch_updates_parents(self) -> None:
        scenario1 = dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
        ).save()

        scenario2 = dfiq.DFIQScenario(
            name="mock_scenario2",
            dfiq_id="S1222",
            dfiq_version="1.0.0",
            description="desc",
        ).save()

        facet = dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["S1003"],
        ).save()

        facet.update_parents()

        facet.parent_ids = ["S1222"]

        response = client.patch(
            f"/api/v2/dfiq/{facet.id}",
            json={"dfiq_yaml": facet.to_yaml(), "dfiq_type": facet.type},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["parent_ids"], ["S1222"])
        self.assertEqual(data["dfiq_id"], facet.dfiq_id)
        self.assertEqual(data["id"], facet.id)

        vertices, edges, total = scenario1.neighbors()
        self.assertEqual(len(vertices), 0)
        self.assertEqual(total, 0)

        vertices, edges, total = scenario2.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[f"dfiq/{facet.id}"].dfiq_id, "F1005")
        self.assertEqual(edges[0][0].type, "facet")
        self.assertEqual(edges[0][0].description, "Uses DFIQ facet")
        self.assertEqual(total, 1)
