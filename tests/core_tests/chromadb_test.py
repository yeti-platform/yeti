import unittest
from unittest import mock
import chromadb

from core import database_arango
from core.schemas import entity
from plugins.analytics.public.chromadb_indexer import ChromaDBIndexer
from core.web.apiv2.search import semantic_search, SemanticSearchRequest

class ChromaDBTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.chroma_client = chromadb.EphemeralClient()
        try:
            self.chroma_client.delete_collection("yeti_semantic_search")
        except Exception:
            pass

    def tearDown(self) -> None:
        try:
            self.chroma_client.delete_collection("yeti_semantic_search")
        except Exception:
            pass

    @mock.patch("core.chromadb_client.get_client")
    def test_end_to_end_semantic_search(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client
        
        # 1. Save an Entity
        ent = entity.save(name="APT28", type="threat-actor", description="A russian threat actor.", tags=["russia"])
        
        # 2. Index using ChromaDBIndexer
        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()
        
        # Check that it is indexed in chroma
        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.count(), 1)
        
        # 3. Retrieve using Semantic Search endpoint
        req = SemanticSearchRequest(query="russian actor", count=10)
        resp = semantic_search(req)
        
        self.assertEqual(resp.total, 1)
        self.assertEqual(resp.results[0]["name"], "APT28")

    @mock.patch("core.chromadb_client.get_client")
    def test_indexing_multiple_entities(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client
        
        # Saving various objects
        entity.save(name="Trickbot", type="malware", description="A banking trojan")
        entity.save(name="Emotet", type="malware", description="Botnet")
        entity.save(name="APT29", type="threat-actor", description="Cozy Bear")

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()
        
        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.count(), 3)
        
        # Make a search targeting just the trojan
        req = SemanticSearchRequest(query="banking malware", count=1)
        resp = semantic_search(req)
        
        self.assertEqual(resp.total, 1)
        self.assertEqual(resp.results[0]["name"], "Trickbot")

    @mock.patch("core.chromadb_client.get_client")
    def test_dfiq_scenario_indexing(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQScenario, DFIQQuestion
        
        # 1. Create a Scenario
        scenario = DFIQScenario.from_yaml('''
type: scenario
id: S0101
dfiq_version: 1.0.0
name: Ransomware Investigation
description: Overall scenario for ransomware
uuid: uuid-scenario
''').save()
        
        # 2. Create a Question with parent_ids pointing to the scenario
        question = DFIQQuestion.from_yaml('''
type: question
id: Q0101
dfiq_version: 1.0.0
name: Initial Access Vector
description: How did they get in exactly?
uuid: uuid-question
parent_ids:
  - S0101
''').save()
        
        question.update_parents()

        # 3. Index it!
        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()
        
        # 4. Search for the description of the *question*
        # Because we index neighbors, the scenario's text document should include the question's text
        req = SemanticSearchRequest(query="How did they get in exactly?", count=10)
        resp = semantic_search(req)
        
        # We expect the scenario to be returned because it has the question as a neighbor
        # And the question too!
        returned_names = [r["name"] for r in resp.results]
        self.assertIn("Ransomware Investigation", returned_names)
        self.assertIn("Initial Access Vector", returned_names)

