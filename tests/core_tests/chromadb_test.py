import unittest
from unittest import mock

import chromadb
from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity, rbac, roles, user
from core.web import webapp
from plugins.analytics.public.chromadb_indexer import ChromaDBIndexer

client = TestClient(webapp.app)


class ChromaDBTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.chroma_client = chromadb.EphemeralClient()
        try:
            self.chroma_client.delete_collection("yeti_semantic_search")
        except Exception:
            pass

        u = user.UserSensitive(username="test", password="test", enabled=True).save()
        apikey = u.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def tearDown(self) -> None:
        try:
            self.chroma_client.delete_collection("yeti_semantic_search")
        except Exception:
            pass

    @mock.patch("core.chromadb_client.get_client")
    def test_end_to_end_semantic_search(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client

        # 1. Save an Entity
        entity.save(
            name="APT28",
            type="threat-actor",
            description="A russian threat actor.",
            tags=["russia"],
        )

        # 2. Index using ChromaDBIndexer
        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        # Check that it is indexed in chroma
        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.count(), 1)

        # 3. Retrieve using Semantic Search endpoint
        response = client.post(
            "/api/v2/search/semantic", json={"query": "russian actor", "count": 10}
        )
        data = response.json()

        self.assertEqual(data["total"], 1)
        self.assertEqual(data["results"][0]["name"], "APT28")

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
        response = client.post(
            "/api/v2/search/semantic", json={"query": "banking malware", "count": 1}
        )
        data = response.json()

        self.assertEqual(data["total"], 1)
        self.assertEqual(data["results"][0]["name"], "Trickbot")
        self.assertIn("semantic_score", data["results"][0])

    @mock.patch("core.chromadb_client.get_client")
    def test_semantic_score_ranks_results_most_to_least_similar(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client

        entity.save(
            name="Trickbot",
            type="malware",
            description="A banking trojan that steals credentials",
        )
        entity.save(
            name="RandomUnrelated",
            type="malware",
            description="Completely unrelated fnord",
        )

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "a banking trojan stealing credentials", "count": 2},
        )
        data = response.json()

        scores = [r["semantic_score"] for r in data["results"]]
        # Higher score first (most similar), and the trojan -- an
        # near-exact match to the query -- should score above the
        # unrelated entity.
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(data["results"][0]["name"], "Trickbot")

    @mock.patch("core.chromadb_client.get_client")
    def test_dfiq_scenario_indexing(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQQuestion, DFIQScenario

        # 1. Create a Scenario
        DFIQScenario.from_yaml("""
type: scenario
id: S0101
dfiq_version: 1.0.0
name: Ransomware Investigation
description: Overall scenario for ransomware
uuid: 00000000-0000-4000-8000-000000000001
""").save()

        # 2. Create a Question with parent_ids pointing to the scenario
        question = DFIQQuestion.from_yaml("""
type: question
id: Q0101
dfiq_version: 1.0.0
name: Initial Access Vector
description: How did they get in exactly?
uuid: 00000000-0000-4000-8000-000000000002
parent_ids:
  - S0101
""").save()

        question.update_parents()

        # 3. Index it!
        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        # 4. Search for the description of the *question*
        # Because we index neighbors, the scenario's text document should include the question's text
        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "How did they get in exactly?", "count": 10},
        )
        data = response.json()

        # We expect the scenario to be returned because it has the question as a neighbor
        # And the question too!
        returned_names = [r["name"] for r in data["results"]]
        self.assertIn("Ransomware Investigation", returned_names)
        self.assertIn("Initial Access Vector", returned_names)

    @mock.patch("core.chromadb_client.get_client")
    def test_semantic_search_respects_acls(self, mock_get_client):
        """A candidate the calling user has no READ permission on must not
        be returned, even though ChromaDB itself knows nothing about ACLs.
        """
        mock_get_client.return_value = self.chroma_client
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True
        try:
            # entity.save() writes straight to Arango, bypassing the API
            # layer's automatic ACL grant -- neither object has any ACL
            # edges until we add one explicitly below.
            visible = entity.save(
                name="VisibleMalware",
                type="malware",
                description="A visible piece of malware",
            )
            entity.save(
                name="HiddenMalware",
                type="malware",
                description="A hidden piece of malware",
            )

            requesting_user = user.UserSensitive.find(username="test")
            requesting_user.link_to_acl(visible, roles.Role.READER)

            indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
            indexer.run()

            response = client.post(
                "/api/v2/search/semantic", json={"query": "malware", "count": 10}
            )
            data = response.json()
            names = [r["name"] for r in data["results"]]

            self.assertIn("VisibleMalware", names)
            self.assertNotIn("HiddenMalware", names)
        finally:
            rbac.RBAC_ENABLED = False
            database_arango.RBAC_ENABLED = False

    @mock.patch("core.chromadb_client.get_client")
    def test_semantic_search_admin_bypasses_acls(self, mock_get_client):
        """An admin sees every candidate regardless of ACLs."""
        mock_get_client.return_value = self.chroma_client
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True
        try:
            entity.save(
                name="UnownedMalware",
                type="malware",
                description="Nobody's granted access to this",
            )

            admin = user.UserSensitive(
                username="admin", password="admin", admin=True, enabled=True
            ).save()
            admin_apikey = admin.create_api_key("default")
            token_data = client.post(
                "/api/v2/auth/api-token", headers={"x-yeti-apikey": admin_apikey}
            ).json()

            indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
            indexer.run()

            response = client.post(
                "/api/v2/search/semantic",
                json={"query": "malware", "count": 10},
                headers={"Authorization": "Bearer " + token_data["access_token"]},
            )
            data = response.json()
            names = [r["name"] for r in data["results"]]

            self.assertIn("UnownedMalware", names)
        finally:
            rbac.RBAC_ENABLED = False
            database_arango.RBAC_ENABLED = False


class ChromaDBClientTest(unittest.TestCase):
    @mock.patch("core.chromadb_client.chromadb.PersistentClient")
    @mock.patch("core.chromadb_client.SharedSystemClient.clear_system_cache")
    @mock.patch("os.path.exists", return_value=True)
    def test_get_client_clears_stale_process_cache(
        self, mock_exists, mock_clear_cache, mock_persistent_client
    ):
        """get_client() must evict chromadb's process-wide cached System
        before constructing a client. PersistentClient caches its
        connection per Python process, so without this, a long-running
        process (the API server) would keep serving whatever snapshot it
        had cached at its own startup, oblivious to writes made by a
        different process (the celery worker running the scheduled
        indexer) -- verified manually against a live index: querying from
        an already-running process missed a document written seconds
        earlier by a separate process, until the cache was cleared.
        """
        from core.chromadb_client import get_client

        get_client()

        mock_clear_cache.assert_called_once()
