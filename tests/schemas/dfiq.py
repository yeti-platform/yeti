import datetime
import unittest

import yaml

from core import database_arango
from core.schemas.dfiq import DFIQBase, DFIQFacet, DFIQQuestion, DFIQScenario, DFIQApproach, DFIQType

class DFIQTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_dfiq_scenario(self) -> None:
        with open("tests/schemas/dfiq_data/S1003.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQScenario.from_yaml(yaml_string).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "scenario1")
        self.assertEqual(result.dfiq_version, "1.0.0")
        self.assertEqual(result.description, "Long description 1\n")
        self.assertEqual(result.type, DFIQType.scenario)
        self.assertEqual(result.dfiq_tags, ['tag1', 'tag2', 'tag3'])

    def test_dfiq_facet(self) -> None:
        with open("tests/schemas/dfiq_data/F1005.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQFacet.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "facet1")
        self.assertEqual(result.description, "Long description of facet1\n")
        self.assertEqual(result.dfiq_id, "F1005")
        self.assertEqual(result.dfiq_version, "1.0.0")
        self.assertEqual(result.dfiq_tags, ["web browser"])
        self.assertEqual(result.parent_ids, ["S1003"])
        self.assertEqual(result.type, DFIQType.facet)

    def test_dfiq_question(self) -> None:
        with open("tests/schemas/dfiq_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQQuestion.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "What is a question?")
        self.assertEqual(result.description, "")
        self.assertEqual(result.dfiq_id, "Q1020")
        self.assertEqual(result.dfiq_version, "1.0.0")
        self.assertEqual(result.dfiq_tags, ["web browser"])
        self.assertEqual(result.parent_ids, ["F1005"])
        self.assertEqual(result.type, DFIQType.question)

    def test_dfiq_approach(self) -> None:
        with open("tests/schemas/dfiq_data/Q1020.10.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQApproach.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "Approach1")
        self.assertEqual(result.description.summary, "Description for approach")
        self.assertEqual(result.description.details, "Details for approach\n")
        self.assertEqual(result.description.references, ['ref1', 'ref2'])

        self.assertEqual(result.view.data[0].type, "artifact")
        self.assertEqual(result.view.data[0].value, "RandomArtifact")
        self.assertEqual(result.view.data[1].type, "description")
        self.assertEqual(result.view.data[1].value, "Random description")
        self.assertEqual(result.view.notes.covered, ["Covered1", "Covered2", "Covered3"])
        self.assertEqual(result.view.notes.not_covered, ["Not covered1", "Not covered2"])
        self.assertEqual(result.view.processors[0].name, "processor1")
        self.assertEqual(result.view.processors[0].options[0].type, "parsers")
        self.assertEqual(result.view.processors[0].options[0].value, "parser1option")
        self.assertEqual(result.view.processors[0].analysis[0].name, "OpenSearch")
        self.assertEqual(result.view.processors[0].analysis[0].steps[0].description, "random parser description")
        self.assertEqual(result.view.processors[0].analysis[0].steps[0].type, "opensearch-query")
        self.assertEqual(result.view.processors[0].analysis[0].steps[0].value, "data_type:(\"fs:stat\")")
        self.assertEqual(result.view.processors[0].analysis[1].steps[0].description, "random step description")
        self.assertEqual(result.view.processors[0].analysis[1].steps[0].type, "pandas")
        self.assertEqual(result.view.processors[0].analysis[1].steps[0].value, """query('data_type in ("fs:stat")')""")

        self.assertEqual(result.view.processors[1].analysis[0].steps[0].description, "something else\n")



    # def test_dfiq_approach(self) -> None:
    #     result = DFIQApproach(
    #         name="approach1",
    #         description=DFIQApproachDescription(
    #             description="description",
    #             examples=["example1", "example2"],
    #             references=["reference1", "reference2"],
    #             notes=["note1", "note2"],
    #         ),
    #         view=DFIQApproachView(
    #             name="view1",
    #             description="description",
    #             examples=["example1", "example2"],
    #             references=["reference1", "reference2"],
    #             notes=["note1", "note2"],
    #         ),
    #         dfiq_id="1234",
    #         dfiq_version="1.0",
    #         dfiq_tags=["tag1", "tag2"],
    #         contributors=["contributor1"],
    #         parent_ids=["1234"],
    #     ).save()
    #     self.assertIsNotNone(result.id)
    #     self.assertIsNotNone(result.created)
    #     self.assertEqual(result.name, "approach1")
    #     self.assertEqual(result.type, DFIQType.approach)
