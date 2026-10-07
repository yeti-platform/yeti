import logging
from datetime import timedelta
from typing import Literal

from core import chromadb_client, taskmanager
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

    def write_in_batches(self, collection, batch_size: int, ids, docs, metadatas):
        """Upserts documents in chunks no larger than ChromaDB will accept.

        ChromaDB's SQLite backend binds a fixed number of host parameters per
        record, so a write is capped at SQLITE_MAX_VARIABLE_NUMBER divided by
        that -- 5461 documents on current SQLite. It is a hard limit of the
        storage layer rather than a tunable, and exceeding it raises instead of
        writing anything, so the whole index goes stale rather than degrading.
        The cap is read from the client because the divisor is ChromaDB's
        internal detail and the numerator differs on older SQLite builds.
        """
        for start in range(0, len(ids), batch_size):
            end = start + batch_size
            collection.upsert(
                documents=docs[start:end],
                ids=ids[start:end],
                metadatas=metadatas[start:end],
            )

    def read_in_batches(
        self, collection, batch_size: int
    ) -> dict[str, tuple[str | None, dict]]:
        """Returns every indexed document's text and metadata, keyed by id.

        Reading the index back has a ceiling of its own. When metadata is
        requested, ChromaDB's SQLite backend looks the returned records up
        again with one bound parameter per record, so a read of more than
        SQLITE_MAX_VARIABLE_NUMBER documents -- 32766 on current SQLite --
        fails inside the backend. Unlike writes, nothing checks that
        client-side, so it fails there rather than with a clear client error,
        and a change splitting the lookup inside ChromaDB was declined
        (chroma-core/chroma#7687). The write cap is reused as the page size:
        it is that same limit divided by the parameters bound per written
        record, so a page always fits.

        Paging by offset never issues an unbounded query, so a per-query cap
        like the one ChromaDB's maintainers suggested there would not break
        it outright. Pages follow the
        SQLite backend's embeddings.id order, which re-upserting an existing id
        does not change. Deleting between pages would shift later records past
        the reader, so callers must read everything before deleting anything.
        A delete from elsewhere mid-read can only make this pass miss
        documents, so at worst a stale one survives until the next pass.

        The text comes back with the metadata so that run() can tell which
        documents changed without embedding anything. It rides on the same
        lookup, and measured at 75,000 documents it added nothing to the read.
        """
        indexed: dict[str, tuple[str | None, dict]] = {}
        offset = 0
        while True:
            page = collection.get(
                include=["documents", "metadatas"], limit=batch_size, offset=offset
            )
            if not page["ids"]:
                return indexed
            for document_id, document, metadata in zip(
                page["ids"], page["documents"], page["metadatas"]
            ):
                indexed[document_id] = (document, metadata or {})
            offset += len(page["ids"])

    def changed_documents(self, indexed, ids, docs, metadatas) -> list[int]:
        """Returns the positions of the documents an upsert would change.

        Upserting a document embeds it -- client-side, before the request --
        whether or not its text changed, because ChromaDB has no way to tell.
        Embedding is nearly the whole cost of a pass, and most passes change
        almost nothing, so only what would change is written.

        The comparison is against what the index holds rather than a
        fingerprint of what was last written. ChromaDB returns stored text
        exactly as it was written, so a record is rewritten whatever made it
        differ -- an edit, a change to how semantic_documents() composes text,
        an index restored from an older snapshot -- the same reconcile
        prune_deleted does for deletions. Metadata is compared as well as
        text: the embedding depends on the text alone, but search filters and
        groups on the metadata.

        What is asked is whether the upsert would change the stored record,
        not whether the record equals what would be written. Upsert merges
        the metadata it is given into what is stored and deletes a key given
        as None, so every key written here has to hold its value already (or,
        for None, be absent), while keys this indexer does not write are
        ignored: an upsert cannot remove them, so comparing them would find a
        record with one left over from an older indexer changed on every pass.

        The embedding model is not compared: a vector is only recomputed when
        its document changes, so changing the model means rebuilding the
        index.
        """
        changed = []
        for position, document_id in enumerate(ids):
            stored = indexed.get(document_id)
            if (
                stored is None
                or stored[0] != docs[position]
                or any(
                    stored[1].get(key) != value
                    for key, value in metadatas[position].items()
                )
            ):
                changed.append(position)
        return changed

    def run(self, params: dict = {}):
        client = chromadb_client.get_client()
        collection = chromadb_client.get_semantic_collection(client)
        batch_size = client.get_max_batch_size()
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

        # One read, before writing: it tells unchanged documents apart, and
        # pruning reuses it rather than reading the whole index again.
        indexed = self.read_in_batches(collection, batch_size)
        changed = self.changed_documents(indexed, ids, docs, metadatas)
        # Logged even when it is 0: that is how an operator can tell unchanged
        # documents are being skipped rather than silently re-embedded.
        logging.info(f"{len(changed)} of {len(ids)} documents changed")
        if changed:
            self.write_in_batches(
                collection,
                batch_size,
                [ids[position] for position in changed],
                [docs[position] for position in changed],
                [metadatas[position] for position in changed],
            )

        self.prune_deleted(
            collection,
            indexed,
            batch_size=batch_size,
            live_object_ids={obj.extended_id for obj in objects_to_index},
            live_document_ids=set(ids),
            documented_object_ids=documented,
        )

    def prune_deleted(
        self,
        collection,
        indexed: dict[str, tuple[str | None, dict]],
        batch_size: int,
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

        `indexed` is what read_in_batches returned before this run wrote
        anything, so it can predate a correction the run has since made.

        Returns:
            The number of stale documents removed.
        """
        stale_ids = []
        for document_id, (_, metadata) in indexed.items():
            if document_id in live_document_ids:
                # Generated this run, so it belongs to a live object and is
                # never stale. The snapshot says otherwise when the stored
                # owner had drifted: the record was rewritten after the read,
                # and judging it by the owner that write replaced would delete
                # the document the run had just repaired.
                continue
            owner = metadata.get("extended_id")
            if owner not in live_object_ids:
                stale_ids.append(document_id)
            elif owner in documented_object_ids:
                stale_ids.append(document_id)

        if not stale_ids:
            return 0

        logging.info(f"Pruning {len(stale_ids)} stale documents from ChromaDB...")
        # Deletes are written through the same batch-limited path as upserts.
        for start in range(0, len(stale_ids), batch_size):
            collection.delete(ids=stale_ids[start : start + batch_size])
        return len(stale_ids)


taskmanager.TaskManager.register_task(ChromaDBIndexer)
