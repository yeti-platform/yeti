import logging
from datetime import timedelta
from typing import Literal

from core import taskmanager
from core.chromadb_client import get_semantic_collection
from core.schemas import task
from core.schemas.dfiq import DFIQBase
from core.schemas.entity import Entity
from core.schemas.indicator import Indicator


class ChromaDBIndexer(task.AnalyticsTask):
    type: Literal["analytics"] = "analytics"
    _defaults = {
        "frequency": timedelta(minutes=10),
        "type": "analytics",
        "description": "Indexes Objects into ChromaDB for Semantic Search",
    }

    acts_on: list[str] = [
        "campaign",
        "malware",
        "threat-actor",
        "intrusion-set",
        "tool",
        "vulnerability",
        "indicator",
        "dfiq-question",
        "dfiq-approach",
        "dfiq-scenario",
        "dfiq-facet",
    ]

    def build_object_documents(self, yeti_obj) -> list[tuple[str, str]]:
        """Returns the (suffix, text) documents to embed for an object.

        The object decides how it wants to be represented -- see
        YetiBaseModel.semantic_documents() -- so type-specific knowledge
        (a DFIQ question emitting one document per approach, say) lives with
        the type rather than here.

        Neighbour text is deliberately not included. It used to be appended to
        every document, on the theory that an object should be findable by the
        things it links to. Measured against real data it did the opposite: it
        pulled each vector toward the average of its neighbourhood, so objects
        ranked *worse* for queries matching their own name and description.
        Removing it moved the "Suspicious DNS Query" scenario from second place
        to first for a query naming it almost exactly, and raised an unrelated
        question's score for its own subject matter from 0.36 to 0.61. The
        graph already answers "what is this related to" precisely, and callers
        who want that can traverse it.
        """
        return yeti_obj.semantic_documents()

    def run(self, params: dict = {}):
        collection = get_semantic_collection()
        objects_to_index = []
        for cls in [Entity, Indicator, DFIQBase]:
            objects, _ = cls.filter({})
            objects_to_index.extend(objects)

        docs = []
        ids = []
        metadatas = []
        documented = set()

        for obj in objects_to_index:
            try:
                for suffix, document in self.build_object_documents(obj):
                    docs.append(document)
                    # One object can produce several vectors, so the id is
                    # namespaced per document; extended_id in the metadata is
                    # what ties them back together for search and pruning.
                    ids.append(f"{obj.extended_id}#{suffix}")
                    metadatas.append(
                        {
                            "id": obj.id,
                            "extended_id": obj.extended_id,
                            "chunk": suffix,
                            "collection": obj._collection_name,
                            "type": getattr(obj, "type", "unknown"),
                        }
                    )
                documented.add(obj.extended_id)
            except Exception as e:
                logging.error(f"Error building document for {obj.id}: {e}")

        if ids:
            logging.info(f"Upserting {len(ids)} documents into ChromaDB...")
            collection.upsert(documents=docs, ids=ids, metadatas=metadatas)

        self.prune_deleted(
            collection,
            live_object_ids={obj.extended_id for obj in objects_to_index},
            live_document_ids=set(ids),
            documented_object_ids=documented,
        )

    def prune_deleted(
        self,
        collection,
        live_object_ids: set[str],
        live_document_ids: set[str],
        documented_object_ids: set[str],
    ) -> int:
        """Removes embeddings that no longer correspond to anything.

        Indexing is upsert-only, so anything that disappears from Yeti leaves
        its embedding behind. Those orphans never surface in results -- the
        endpoint drops any hit it can't load -- but they still occupy slots in
        the fixed-size nearest-neighbour window, so a query asking for N
        results can quietly come back with fewer.

        Reconciling against the live set (rather than reacting to delete
        events) also repairs drift from any cause: a missed event, an object
        removed while the indexer was down, or an index restored from an
        older snapshot.

        Two different things can go stale, because one object owns several
        documents:

        - the whole object is gone, so every document under it should go;
        - the object remains but no longer produces a given document, e.g. a
          DFIQ question that dropped an approach. Its id simply stops being
          generated, and nothing else would ever clean it up.

        Objects whose documents failed to build this run are deliberately left
        alone: they still exist, and a transient error must not evict what was
        indexed for them previously.

        Returns:
            The number of stale documents removed.
        """
        indexed = collection.get(include=["metadatas"])

        stale_ids = []
        for document_id, metadata in zip(indexed["ids"], indexed["metadatas"]):
            owner = (metadata or {}).get("extended_id")
            if owner not in live_object_ids:
                stale_ids.append(document_id)
            elif (
                owner in documented_object_ids and document_id not in live_document_ids
            ):
                stale_ids.append(document_id)

        if not stale_ids:
            return 0

        logging.info(f"Pruning {len(stale_ids)} stale documents from ChromaDB...")
        collection.delete(ids=stale_ids)
        return len(stale_ids)


taskmanager.TaskManager.register_task(ChromaDBIndexer)
