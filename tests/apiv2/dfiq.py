import io
import logging
import sys
import unittest
from zipfile import ZipFile

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
            dfiq_yaml="mock",
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
            dfiq_yaml="mock",
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
            dfiq_yaml="mock",
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
            dfiq_yaml="mock",
        ).save()

        scenario2 = dfiq.DFIQScenario(
            name="mock_scenario2",
            dfiq_id="S1222",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        facet = dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
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

    def test_dfiq_patch_approach_updates_parents(self) -> None:
        dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
        ).save()

        question1 = dfiq.DFIQQuestion(
            name="mock_question",
            dfiq_id="Q1020",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
        ).save()

        question2 = dfiq.DFIQQuestion(
            name="mock_question2",
            dfiq_id="Q1022",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
        ).save()

        with open("tests/dfiq_test_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()
        approach = dfiq.DFIQApproach.from_yaml(yaml_string).save()
        approach.update_parents()

        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[f"dfiq/{question1.id}"].dfiq_id, "Q1020")
        self.assertEqual(edges[0][0].type, "approach")
        self.assertEqual(edges[0][0].description, "Uses DFIQ approach")
        self.assertEqual(total, 1)

        approach.dfiq_id = "Q1022.10"
        response = client.patch(
            f"/api/v2/dfiq/{approach.id}",
            json={
                "dfiq_yaml": approach.to_yaml(),
                "dfiq_type": approach.type,
                "update_indicators": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["dfiq_id"], "Q1022.10")
        self.assertEqual(data["id"], approach.id)

        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(vertices[f"dfiq/{question2.id}"].dfiq_id, "Q1022")
        self.assertEqual(edges[0][0].type, "approach")
        self.assertEqual(edges[0][0].description, "Uses DFIQ approach")
        self.assertEqual(total, 1)

    def test_dfiq_patch_approach_updates_indicators(self) -> None:
        dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQQuestion(
            name="mock_question",
            dfiq_id="Q1020",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
        ).save()

        with open("tests/dfiq_test_data/Q1020.10_no_indicators.yaml", "r") as f:
            yaml_string = f.read()
        approach = dfiq.DFIQApproach.from_yaml(yaml_string).save()
        approach.update_parents()

        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(total, 1)

        with open("tests/dfiq_test_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()

        response = client.patch(
            f"/api/v2/dfiq/{approach.id}",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": approach.type,
                "update_indicators": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(total, 1)

        response = client.patch(
            f"/api/v2/dfiq/{approach.id}",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": approach.type,
                "update_indicators": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 4)
        self.assertEqual(total, 4)

    def test_dfiq_post_approach(self):
        dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQQuestion(
            name="mock_question",
            dfiq_id="Q1020",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
        ).save()

        with open("tests/dfiq_test_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.approach,
                "update_indicators": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        approach = dfiq.DFIQApproach.get(id=data["id"])
        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 1)
        approach.delete()

        response = client.post(
            "/api/v2/dfiq/from_yaml",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.approach,
                "update_indicators": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        approach = dfiq.DFIQApproach.get(id=data["id"])
        vertices, edges, total = approach.neighbors()
        self.assertEqual(len(vertices), 4)

    def test_wrong_parent(self) -> None:
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
        self.assertEqual(response.status_code, 400, data)
        self.assertEqual(data, {"detail": "Missing parent(s) ['S1003'] for F1005"})

    def test_wrong_parent_approach(self) -> None:
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
        self.assertEqual(response.status_code, 400, data)
        self.assertEqual(data, {"detail": "Missing parent(s) ['Q1020'] for Q1020.10"})

    def test_valid_dfiq_yaml(self) -> None:
        with open("tests/dfiq_test_data/S1003.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/validate",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.scenario,
                "check_id": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["valid"], True)

        with open("tests/dfiq_test_data/F1005.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/validate",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.facet,
                "check_id": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["valid"], True)

        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/validate",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.question,
                "check_id": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["valid"], True)

        with open("tests/dfiq_test_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()

        response = client.post(
            "/api/v2/dfiq/validate",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": dfiq.DFIQType.approach,
                "check_id": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["valid"], True)

    def test_upload_dfiq_archive(self):
        zip_archive = open("tests/dfiq_test_data/dfiq_test_data.zip", "rb")
        response = client.post(
            "/api/v2/dfiq/from_archive",
            files={"archive": ("test_archive.zip", zip_archive, "application/zip")},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data, {"total_added": 4})

    def test_to_archive(self):
        dfiq.DFIQScenario(
            name="public_scenario",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
            internal=False,
        ).save()

        dfiq.DFIQScenario(
            name="private_scenario",
            dfiq_id="S0003",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
            internal=True,
        ).save()

        dfiq.DFIQQuestion(
            name="mock_question",
            dfiq_id="Q1020",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
        ).save()

        response = client.post("/api/v2/dfiq/to_archive", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/zip")
        self.assertEqual(
            response.headers["content-disposition"], 'attachment; filename="dfiq.zip"'
        )

        with ZipFile(io.BytesIO(response.content)) as archive:
            files = archive.namelist()
            self.assertEqual(len(files), 3)
            self.assertIn("public/scenario/S1003.yaml", files)
            self.assertIn("internal/scenario/S0003.yaml", files)
            self.assertIn("public/question/Q1020.yaml", files)

            with archive.open("public/scenario/S1003.yaml") as f:
                content = f.read().decode("utf-8")
                self.assertIn("public_scenario", content)
            with archive.open("internal/scenario/S0003.yaml") as f:
                content = f.read().decode("utf-8")
                self.assertIn("private_scenario", content)
            with archive.open("public/question/Q1020.yaml") as f:
                content = f.read().decode("utf-8")
                self.assertIn("mock_question", content)
