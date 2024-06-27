import unittest

import yaml

from core import database_arango
from core.schemas.dfiq import (
    DFIQApproach,
    DFIQFacet,
    DFIQQuestion,
    DFIQScenario,
    DFIQType,
)


class DFIQTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_dfiq_scenario(self) -> None:
        with open("tests/dfiq_test_data/S1003.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQScenario.from_yaml(yaml_string).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "scenario1")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(str(result.uuid), "2ee16263-56f8-49a5-9b33-d1a2dd8b829c")
        self.assertEqual(result.description, "Long description 1\n")
        self.assertEqual(result.type, DFIQType.scenario)
        self.assertEqual(result.dfiq_tags, ["Tag1", "Tag2", "Tag3"])

    def test_dfiq_scenario_no_id(self) -> None:
        with open("tests/dfiq_test_data/DFIQ_Scenario_no_id.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQScenario.from_yaml(yaml_string).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "scenario1")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(str(result.uuid), "2ee16263-56f8-49a5-9b33-d1a2dd8b829c")
        self.assertEqual(result.description, "Long description 1\n")
        self.assertEqual(result.type, DFIQType.scenario)
        self.assertEqual(result.dfiq_tags, ["Tag1", "Tag2", "Tag3"])

    def test_dfiq_facet(self) -> None:
        with open("tests/dfiq_test_data/F1005.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQFacet.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "facet1")
        self.assertEqual(result.description, "Long description of facet1\n")
        self.assertEqual(result.dfiq_id, "F1005")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(str(result.uuid), "b2bab31f-1670-4297-8cb1-685747a13468")
        self.assertEqual(result.dfiq_tags, ["Web Browser"])
        self.assertEqual(result.parent_ids, ["S1003"])
        self.assertEqual(result.type, DFIQType.facet)

    def test_dfiq_question(self) -> None:
        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQQuestion.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "What is a question?")
        self.assertEqual(result.description, None)
        self.assertEqual(str(result.uuid), "bd46ce6e-c933-46e5-960c-36945aaef401")
        self.assertEqual(result.dfiq_id, "Q1020")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(result.dfiq_tags, ["Web Browser"])
        self.assertEqual(result.parent_ids, ["F1005"])
        self.assertEqual(result.type, DFIQType.question)

    def test_dfiq_approach(self) -> None:
        with open("tests/dfiq_test_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQApproach.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertEquals(result.uuid, "292500f7-9d54-40ca-8254-34821e9b5c4e")
        self.assertEquals(result.parent_id, "bd46ce6e-c933-46e5-960c-36945aaef401")
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "Approach1")
        self.assertEqual(result.description.summary, "Description for approach")
        self.assertEqual(result.description.details, "Details for approach\n")
        self.assertEqual(result.description.references, ["ref1", "ref2"])

        self.assertEqual(result.view.data[0].type, "artifact")
        self.assertEqual(result.view.data[0].value, "RandomArtifact")
        self.assertEqual(result.view.data[1].type, "description")
        self.assertEqual(result.view.data[1].value, "Random description")
        self.assertEqual(
            result.view.notes.covered, ["Covered1", "Covered2", "Covered3"]
        )
        self.assertEqual(
            result.view.notes.not_covered, ["Not covered1", "Not covered2"]
        )
        self.assertEqual(result.view.processors[0].name, "processor1")
        self.assertEqual(result.view.processors[0].options[0].type, "parsers")
        self.assertEqual(result.view.processors[0].options[0].value, "parser1option")
        self.assertEqual(result.view.processors[0].analysis[0].name, "OpenSearch")
        self.assertEqual(
            result.view.processors[0].analysis[0].steps[0].description,
            "random parser description",
        )
        self.assertEqual(
            result.view.processors[0].analysis[0].steps[0].type, "opensearch-query"
        )
        self.assertEqual(
            result.view.processors[0].analysis[0].steps[0].value,
            'data_type:("fs:stat")',
        )
        self.assertEqual(
            result.view.processors[0].analysis[1].steps[0].description,
            "random step description",
        )
        self.assertEqual(result.view.processors[0].analysis[1].steps[0].type, "pandas")
        self.assertEqual(
            result.view.processors[0].analysis[1].steps[0].value,
            """query('data_type in ("fs:stat")')""",
        )

        self.assertEqual(
            result.view.processors[1].analysis[0].steps[0].description,
            "something else\n",
        )

    def test_dfiq_conversion_to_yaml(self) -> None:
        self.maxDiff = None
        type_map = [
            (DFIQScenario, "tests/dfiq_test_data/S1003.yaml"),
            (DFIQFacet, "tests/dfiq_test_data/F1005.yaml"),
            (DFIQQuestion, "tests/dfiq_test_data/Q1020.yaml"),
            (DFIQApproach, "tests/dfiq_test_data/Q1020.10.yaml"),
        ]

        for type_, file_path in type_map:
            with open(file_path, "r") as f:
                yaml_string = f.read()

            result = type_.from_yaml(yaml_string).save()

            expected_yaml_string = yaml.dump(yaml.safe_load(yaml_string))
            result_yaml_string = result.to_yaml()
            self.assertEqual(expected_yaml_string, result_yaml_string)
