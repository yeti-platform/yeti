import math
import unittest
from unittest import mock

import chromadb
from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import entity, rbac, roles, user
from core.web import webapp
from plugins.analytics.public.chromadb_indexer import ChromaDBIndexer

client = TestClient(webapp.app)


def sections_by_type(data: dict) -> dict[str, dict]:
    return {section["type"]: section for section in data["sections"]}


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
        sections = sections_by_type(data)

        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["entity"]["results"][0]["name"], "APT28")

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
        sections = sections_by_type(data)

        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["entity"]["results"][0]["name"], "Trickbot")
        self.assertIn("semantic_score", sections["entity"]["results"][0])

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
        sections = sections_by_type(data)
        results = sections["entity"]["results"]

        scores = [r["semantic_score"] for r in results]
        # Higher score first (most similar), and the trojan -- an
        # near-exact match to the query -- should score above the
        # unrelated entity.
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(results[0]["name"], "Trickbot")

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

        # 4. Both objects are indexed and searchable in their own right.
        # (They used to be linked through neighbour text embedded into the
        # scenario's document; that was removed because it dragged every
        # vector toward its neighbourhood and hurt ranking. Relationships are
        # the graph's job, not the embedding's.)
        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "How did they get in exactly?", "count": 10},
        )
        data = response.json()
        sections = sections_by_type(data)

        returned_names = [r["name"] for r in sections["dfiq"]["results"]]
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
            sections = sections_by_type(data)
            names = [r["name"] for r in sections["entity"]["results"]]

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
            sections = sections_by_type(data)
            names = [r["name"] for r in sections["entity"]["results"]]

            self.assertIn("UnownedMalware", names)
        finally:
            rbac.RBAC_ENABLED = False
            database_arango.RBAC_ENABLED = False

    @mock.patch("core.chromadb_client.get_client")
    def test_root_type_scopes_to_a_single_type(self, mock_get_client):
        """A DFIQ scenario and an entity can both semantically match the
        same query -- root_type must exclude the other type entirely, not
        just deprioritize it.
        """
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQScenario

        entity.save(
            name="Suspicious DNS Malware",
            type="malware",
            description="Malware that performs suspicious DNS queries for C2",
        )
        DFIQScenario.from_yaml("""
type: scenario
id: S0102
dfiq_version: 1.0.0
name: Suspicious DNS Query
description: Investigating a suspicious DNS query
uuid: 00000000-0000-4000-8000-000000000003
""").save()

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        response = client.post(
            "/api/v2/search/semantic",
            json={
                "query": "suspicious DNS query",
                "count": 10,
                "root_type": "dfiq",
            },
        )
        data = response.json()

        self.assertEqual(len(data["sections"]), 1, data)
        self.assertEqual(data["sections"][0]["type"], "dfiq")
        names = [r["name"] for r in data["sections"][0]["results"]]
        self.assertIn("Suspicious DNS Query", names)
        self.assertNotIn("Suspicious DNS Malware", names)

    @mock.patch("core.chromadb_client.get_client")
    def test_unscoped_search_does_not_let_one_type_crowd_out_another(
        self, mock_get_client
    ):
        """A high-volume type (many matching entities) must not push a
        low-volume type's (one matching DFIQ scenario) results out of the
        response -- each type is queried and bounded independently.
        """
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQScenario

        for i in range(8):
            entity.save(
                name=f"DNS Malware {i}",
                type="malware",
                description="Malware that performs suspicious DNS queries for C2",
            )
        DFIQScenario.from_yaml("""
type: scenario
id: S0103
dfiq_version: 1.0.0
name: Suspicious DNS Query
description: Investigating a suspicious DNS query
uuid: 00000000-0000-4000-8000-000000000004
""").save()

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "suspicious DNS query", "count": 1},
        )
        data = response.json()
        sections = sections_by_type(data)

        # The single DFIQ match is present regardless of how many entity
        # matches exist -- it isn't sharing a page with them.
        self.assertEqual(sections["dfiq"]["total"], 1, data)
        self.assertEqual(sections["dfiq"]["results"][0]["name"], "Suspicious DNS Query")
        self.assertEqual(len(sections["entity"]["results"]), 1, data)

    @mock.patch("core.chromadb_client.get_client")
    def test_semantic_scores_stay_within_zero_and_one(self, mock_get_client):
        """Scores are advertised as a 0-1 similarity, and clients are expected
        to threshold on them. A weak-but-real match must land inside that
        range rather than going negative, which is what the previous
        distance-to-score conversion did.
        """
        mock_get_client.return_value = self.chroma_client

        entity.save(name="Trickbot", type="malware", description="A banking trojan")
        entity.save(
            name="RandomUnrelated",
            type="malware",
            description="Completely unrelated fnord",
        )

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "credential stealing banking trojan", "count": 10},
        )
        data = response.json()
        results = sections_by_type(data)["entity"]["results"]

        self.assertEqual(len(results), 2, data)
        for result in results:
            self.assertGreaterEqual(result["semantic_score"], 0.0, result)
            self.assertLessEqual(result["semantic_score"], 1.0, result)

    @mock.patch("core.chromadb_client.get_client")
    def test_index_uses_the_distance_metric_the_score_assumes(self, mock_get_client):
        """_similarity_score converts a *squared euclidean* distance over
        unit-length vectors. Both properties come from ChromaDB defaults we
        never set explicitly, so pin them here: if an upgrade changes either,
        scores would silently become wrong rather than fail.
        """
        mock_get_client.return_value = self.chroma_client

        entity.save(name="Trickbot", type="malware", description="A banking trojan")
        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.configuration_json["hnsw"]["space"], "l2")

        embeddings = collection.get(include=["embeddings"])["embeddings"]
        for embedding in embeddings:
            norm = math.sqrt(sum(value * value for value in embedding))
            self.assertAlmostEqual(norm, 1.0, places=5)

    @mock.patch("core.chromadb_client.get_client")
    def test_deleted_objects_are_pruned_from_the_index(self, mock_get_client):
        mock_get_client.return_value = self.chroma_client

        trickbot = entity.save(
            name="Trickbot", type="malware", description="A banking trojan"
        )
        entity.save(name="Emotet", type="malware", description="Botnet")

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.count(), 2)

        trickbot.delete()
        indexer.run()

        self.assertEqual(collection.count(), 1)
        self.assertNotIn(trickbot.extended_id, collection.get(include=[])["ids"])

        # The surviving object is still searchable.
        response = client.post(
            "/api/v2/search/semantic", json={"query": "botnet", "count": 10}
        )
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["entity"]["results"][0]["name"], "Emotet")

    @mock.patch("core.chromadb_client.get_client")
    def test_orphans_no_longer_consume_the_result_window(self, mock_get_client):
        """A stale embedding used to eat a slot in the fixed-size nearest-
        neighbour window: the endpoint drops hits it can't load, so asking
        for N could return fewer than N even with N live matches available.
        """
        mock_get_client.return_value = self.chroma_client

        doomed = entity.save(
            name="Trickbot", type="malware", description="A banking trojan"
        )
        entity.save(name="Dridex", type="malware", description="A banking trojan")

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        doomed.delete()
        indexer.run()

        # count=1 must return the one live match, not an empty section that
        # spent its only slot on the deleted object (which ranks first for
        # this query, being an exact description match).
        response = client.post(
            "/api/v2/search/semantic", json={"query": "banking trojan", "count": 1}
        )
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["entity"]["results"][0]["name"], "Dridex")

    @mock.patch("core.chromadb_client.get_client")
    def test_pruning_ignores_objects_whose_document_failed_to_build(
        self, mock_get_client
    ):
        """A document that fails to build must not evict its own embedding:
        the object still exists, so the previously-indexed copy should be
        left alone rather than treated as stale.
        """
        mock_get_client.return_value = self.chroma_client

        entity.save(name="Trickbot", type="malware", description="A banking trojan")
        entity.save(name="Emotet", type="malware", description="Botnet")

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.count(), 2)

        # Nothing was deleted, but every document build now fails.
        with mock.patch.object(
            ChromaDBIndexer, "build_object_documents", side_effect=RuntimeError("boom")
        ):
            indexer.run()

        self.assertEqual(collection.count(), 2)

    @mock.patch("core.chromadb_client.get_client")
    def test_question_approaches_are_indexed_as_their_own_documents(
        self, mock_get_client
    ):
        """Approach content -- artifacts, tooling, queries -- only exists
        inside a question's approaches, and is the vocabulary someone
        searching "how do I collect X" actually uses. Each approach gets its
        own vector so it can match without being averaged into the
        question's own text.
        """
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQQuestion

        DFIQQuestion.from_yaml("""
type: question
id: Q0201
dfiq_version: 1.0.0
name: What files were downloaded using a web browser?
description: Downloads question.
uuid: 00000000-0000-4000-8000-000000000101
parent_ids: []
approaches:
  - name: Detect browser downloads via change journal records
    description: Uses NTFS USN journal records.
    steps:
      - name: Collect ForensicArtifact data
        stage: collection
        type: ForensicArtifact
        value: NTFSUSNJournal
      - name: Process data with Plaso
        stage: processing
        type: command
        value: Plaso
""").save()

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        collection = self.chroma_client.get_collection("yeti_semantic_search")
        chunks = {
            m["chunk"] for m in collection.get(include=["metadatas"])["metadatas"]
        }
        self.assertEqual(chunks, {"self", "approach:0"})

        # The artifact/tooling vocabulary appears nowhere in the question's
        # own name or description, so this only matches via the approach.
        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "NTFS USN journal records with Plaso", "count": 5},
        )
        data = response.json()
        results = sections_by_type(data)["dfiq"]["results"]

        self.assertEqual(len(results), 1, data)
        self.assertEqual(
            results[0]["name"], "What files were downloaded using a web browser?"
        )
        self.assertEqual(results[0]["matched_on"], "approach:0")

    @mock.patch("core.chromadb_client.get_client")
    def test_an_object_is_returned_once_however_many_documents_match(
        self, mock_get_client
    ):
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQQuestion

        DFIQQuestion.from_yaml("""
type: question
id: Q0202
dfiq_version: 1.0.0
name: What browser downloads happened?
description: Browser downloads.
uuid: 00000000-0000-4000-8000-000000000102
parent_ids: []
approaches:
  - name: Browser download history
    description: Look at browser download history.
    steps: []
  - name: Browser download artifacts on disk
    description: Look at browser download artifacts.
    steps: []
""").save()

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        # All three documents are strong matches for this query; the object
        # must still come back once.
        response = client.post(
            "/api/v2/search/semantic",
            json={"query": "browser downloads", "count": 5},
        )
        data = response.json()
        results = sections_by_type(data)["dfiq"]["results"]

        self.assertEqual(len(results), 1, data)
        self.assertEqual(results[0]["name"], "What browser downloads happened?")

    @mock.patch("core.chromadb_client.get_client")
    def test_documents_an_object_stops_producing_are_pruned(self, mock_get_client):
        """Chunking adds a second way to go stale: the object survives but
        stops emitting one of its documents. Nothing else would clean that
        up, and the orphan would keep matching.
        """
        mock_get_client.return_value = self.chroma_client
        from core.schemas.dfiq import DFIQQuestion

        question = DFIQQuestion.from_yaml("""
type: question
id: Q0203
dfiq_version: 1.0.0
name: A question with approaches
description: Has two approaches to start with.
uuid: 00000000-0000-4000-8000-000000000103
parent_ids: []
approaches:
  - name: First approach
    description: The first one.
    steps: []
  - name: Second approach
    description: The second one.
    steps: []
""").save()

        indexer = ChromaDBIndexer(name="ChromaDBIndexer", enabled=True)
        indexer.run()

        collection = self.chroma_client.get_collection("yeti_semantic_search")
        self.assertEqual(collection.count(), 3)

        question.approaches = question.approaches[:1]
        question.save()
        indexer.run()

        remaining = {
            m["chunk"] for m in collection.get(include=["metadatas"])["metadatas"]
        }
        self.assertEqual(remaining, {"self", "approach:0"})


class SimilarityScoreTest(unittest.TestCase):
    def test_converts_squared_l2_distance_to_a_bounded_similarity(self):
        from core.web.apiv2.search import _similarity_score

        # Unit vectors: ||a-b||^2 == 2 - 2*cos(a, b), so 0 -> identical,
        # 2 -> orthogonal, 4 -> opposite.
        self.assertEqual(_similarity_score(0.0), 1.0)
        self.assertEqual(_similarity_score(1.0), 0.5)
        self.assertEqual(_similarity_score(2.0), 0.0)

        # Anti-correlated embeddings clamp to 0 rather than going negative.
        self.assertEqual(_similarity_score(3.0), 0.0)
        self.assertEqual(_similarity_score(4.0), 0.0)

    def test_is_monotonically_decreasing_in_distance(self):
        from core.web.apiv2.search import _similarity_score

        scores = [_similarity_score(d / 10) for d in range(0, 21)]
        self.assertEqual(scores, sorted(scores, reverse=True))


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
