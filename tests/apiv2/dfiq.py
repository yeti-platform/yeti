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

    def test_config(self) -> None:
        dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            uuid="fake_facet_uuid",
            dfiq_version="1.1.0",
            description="desc",
            parent_ids=[],
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

        response = client.get("/api/v2/dfiq/config")
        data = response.json()

        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["stage_types"], ["analysis", "collection"])
        self.assertEqual(
            data["step_types"],
            ["ForensicArtifact", "opensearch-query", "opensearch-query-second"],
        )

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
        self.assertEqual(data["dfiq_version"], "1.1.0")
        self.assertEqual(data["description"], "Long description 1\n")
        self.assertEqual(data["type"], dfiq.DFIQType.scenario)
        self.assertEqual(data["dfiq_tags"], ["Tag1", "Tag2", "Tag3"])

    def test_new_dfiq_facet(self) -> None:
        scenario = dfiq.DFIQScenario(
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
                "dfiq_type": dfiq.DFIQType.facet,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data["id"])
        self.assertIsNotNone(data["created"])
        self.assertEqual(data["name"], "facet1")
        self.assertEqual(data["dfiq_id"], "F1005")
        self.assertEqual(data["dfiq_version"], "1.1.0")
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
                "dfiq_type": dfiq.DFIQType.question,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIsNotNone(data["id"])
        self.assertIsNotNone(data["created"])
        self.assertEqual(data["name"], "What is a question?")
        self.assertEqual(data["dfiq_id"], "Q1020")
        self.assertEqual(data["dfiq_version"], "1.1.0")
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

    def test_delete_with_children_ref_uuid(self) -> None:
        scenario = dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            uuid="fake_scenario_uuid",
            dfiq_version="1.1.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        facet = dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            uuid="fake_facet_uuid",
            dfiq_version="1.1.0",
            description="desc",
            parent_ids=["fake_scenario_uuid"],
            dfiq_yaml="mock",
        ).save()

        response = client.delete(f"/api/v2/dfiq/{scenario.id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.get(f"/api/v2/dfiq/{facet.id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["parent_ids"], [])

    def test_delete_with_children_ref_dfiqd(self) -> None:
        scenario = dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            uuid="fake_scenario_uuid",
            dfiq_version="1.1.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        facet = dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            uuid="fake_facet_uuid",
            dfiq_version="1.1.0",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
        ).save()

        response = client.delete(f"/api/v2/dfiq/{scenario.id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        response = client.get(f"/api/v2/dfiq/{facet.id}")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["parent_ids"], [])

    def test_dfiq_patch_updates_parents(self) -> None:
        scenario1 = dfiq.DFIQScenario(
            name="mock_scenario",
            dfiq_id="S1003",
            uuid="fake_scenario_uuid1",
            dfiq_version="1.1.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        scenario2 = dfiq.DFIQScenario(
            name="mock_scenario2",
            dfiq_id="S1222",
            uuid="fake_scenario_uuid2",
            dfiq_version="1.1.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        facet = dfiq.DFIQFacet(
            name="mock_facet",
            dfiq_id="F1005",
            uuid="fake_facet_uuid",
            dfiq_version="1.1.0",
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

    def test_dfiq_patch_question_updates_indicators(self) -> None:
        dfiq.DFIQScenario(
            name="mock_scenario",
            uuid="fake_scenario_uuid",
            dfiq_id="S1003",
            dfiq_version="1.1.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQFacet(
            name="mock_facet",
            uuid="fake_facet_uuid",
            dfiq_version="1.1.0",
            dfiq_id="F1005",
            description="desc",
            parent_ids=["S1003"],
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQQuestion(
            name="What is a question?",
            uuid="bd46ce6e-c933-46e5-960c-36945aaef401",
            dfiq_version="1.1.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
            approaches=[],
        ).save()

        with open("tests/dfiq_test_data/Q1020_no_indicators.yaml", "r") as f:
            yaml_string = f.read()
        question = dfiq.DFIQQuestion.from_yaml(yaml_string).save()
        question.update_parents()

        vertices, edges, total = question.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(total, 1)

        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        response = client.patch(
            f"/api/v2/dfiq/{question.id}",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": question.type,
                "update_indicators": False,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        vertices, edges, total = question.neighbors()
        self.assertEqual(len(vertices), 1)
        self.assertEqual(total, 1)

        response = client.patch(
            f"/api/v2/dfiq/{question.id}",
            json={
                "dfiq_yaml": yaml_string,
                "dfiq_type": question.type,
                "update_indicators": True,
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        vertices, edges, total = question.neighbors()
        self.assertEqual(len(vertices), 3)
        self.assertEqual(total, 3)

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
        self.assertEqual(data, {"detail": "Missing parent(s), provided ['S1003']"})
        existing = dfiq.DFIQFacet.find(dfiq_id="F1005")
        self.assertIsNone(existing)

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

    def test_standalone_question_creation(self):
        with open("tests/dfiq_test_data/Q1020_no_parents.yaml", "r") as f:
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
        self.assertEqual(data["parent_ids"], [])

    def test_upload_dfiq_archive(self):
        zip_archive = open("tests/dfiq_test_data/dfiq_test_data.zip", "rb")
        response = client.post(
            "/api/v2/dfiq/from_archive",
            files={"archive": ("test_archive.zip", zip_archive, "application/zip")},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data, {"total_added": 3})

    def test_to_archive(self):
        dfiq.DFIQScenario(
            name="public_scenario",
            uuid="test_scenario_uuid",
            dfiq_id="S1003",
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQScenario(
            name="private_scenario",
            uuid="test_private_scenario_uuid",
            dfiq_id="S0003",
            dfiq_tags=["internal"],
            dfiq_version="1.0.0",
            description="desc",
            dfiq_yaml="mock",
        ).save()

        dfiq.DFIQQuestion(
            name="semi_private_question",
            uuid="test_question_uuid",
            dfiq_id="Q1020",
            dfiq_version="1.0.0",
            description="desc",
            parent_ids=["F1005"],
            dfiq_yaml="mock",
            approaches=[
                dfiq.DFIQApproach(
                    name="public_approach",
                    description="desc",
                    tags=["public"],
                ),
                dfiq.DFIQApproach(
                    name="internal_approach",
                    description="desc",
                    tags=["internal"],
                ),
            ],
        ).save()

        response = client.post("/api/v2/dfiq/to_archive", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/zip")
        self.assertEqual(
            response.headers["content-disposition"], 'attachment; filename="dfiq.zip"'
        )

        with ZipFile(io.BytesIO(response.content)) as archive:
            files = archive.namelist()
            self.assertEqual(len(files), 4)
            self.assertIn("public/scenarios/test_scenario_uuid.yaml", files)
            self.assertIn("internal/scenarios/test_private_scenario_uuid.yaml", files)
            self.assertIn("public/questions/test_question_uuid.yaml", files)
            self.assertIn("internal/questions/test_question_uuid.yaml", files)

            with archive.open("public/scenarios/test_scenario_uuid.yaml") as f:
                content = f.read().decode("utf-8")
                self.assertIn("public_scenario", content)
            with archive.open(
                "internal/scenarios/test_private_scenario_uuid.yaml"
            ) as f:
                content = f.read().decode("utf-8")
                self.assertIn("private_scenario", content)
            with archive.open("public/questions/test_question_uuid.yaml") as f:
                content = f.read().decode("utf-8")
                self.assertIn("semi_private_question", content)
                self.assertIn("public_approach", content)
                self.assertNotIn("internal_approach", content)
            with archive.open("internal/questions/test_question_uuid.yaml") as f:
                content = f.read().decode("utf-8")
                self.assertIn("semi_private_question", content)
                self.assertIn("public_approach", content)
                self.assertIn("internal_approach", content)
