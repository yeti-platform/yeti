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

    def build_object_document(self, yeti_obj) -> str:
        """Builds a semantic representation of a yeti object including neighbors."""
        parts = []
        if getattr(yeti_obj, "name", None):
            parts.append(f"Name: {yeti_obj.name}")
        if getattr(yeti_obj, "value", None):
            parts.append(f"Value: {yeti_obj.value}")
        if getattr(yeti_obj, "description", None):
            parts.append(f"Description: {yeti_obj.description}")

        tags = getattr(yeti_obj, "tags", [])
        if tags:
            tag_names = [t.name if hasattr(t, "name") else str(t) for t in tags]
            parts.append(f"Tags: {', '.join(tag_names)}")

        try:
            vertices, _, _ = yeti_obj.neighbors()
            neighbor_names = []
            for neighbor in vertices.values():
                val = getattr(neighbor, "name", "") or getattr(neighbor, "value", "")
                desc = getattr(neighbor, "description", "")
                n_str = f"{val} ({desc})" if desc else val
                if n_str:
                    neighbor_names.append(n_str)
            if neighbor_names:
                parts.append("Neighbors: " + " | ".join(neighbor_names))
        except Exception as e:
            logging.error(f"Failed to get neighbors for {yeti_obj.id}: {e}")

        return "\n".join(parts)

    def run(self, params: dict = {}):
        collection = get_semantic_collection()
        objects_to_index = []
        for cls in [Entity, Indicator, DFIQBase]:
            objects, _ = cls.filter({})
            objects_to_index.extend(objects)

        docs = []
        ids = []
        metadatas = []

        for obj in objects_to_index:
            try:
                docs.append(self.build_object_document(obj))
                ids.append(obj.extended_id)
                metadatas.append(
                    {
                        "id": obj.id,
                        "extended_id": obj.extended_id,
                        "collection": obj._collection_name,
                        "type": getattr(obj, "type", "unknown"),
                    }
                )
            except Exception as e:
                logging.error(f"Error building document for {obj.id}: {e}")

        if ids:
            logging.info(f"Upserting {len(ids)} documents into ChromaDB...")
            collection.upsert(documents=docs, ids=ids, metadatas=metadatas)


taskmanager.TaskManager.register_task(ChromaDBIndexer)
