"""Class implementing a YetiConnector interface for ArangoDB."""

import datetime
import json
import logging
import sys
import time
import traceback
from typing import TYPE_CHECKING, Any, Iterable, List, Optional, Tuple, Type, TypeVar

if TYPE_CHECKING:
    from core.schemas import entity, indicator, observable
    from core.schemas.graph import (
        GraphFilter,
        Relationship,
        RelationshipTypes,
        TagRelationship,
    )
    from core.schemas.tag import Tag

import requests
from arango import ArangoClient
from arango.exceptions import DocumentInsertError, GraphCreateError

from core.config.config import yeti_config
from core.events import message
from core.events.producer import producer

from .interfaces import AbstractYetiConnector

CODE_DB_VERSION = 2

LINK_TYPE_TO_GRAPH = {
    "tagged": "tags",
    "stix": "stix",
}

TESTING = "unittest" in sys.modules.keys()

ASYNC_JOB_WAIT_TIME = 0.01

TYetiObject = TypeVar("TYetiObject", bound="ArangoYetiConnector")


class ArangoDatabase:
    """Class that contains the base class for the database.

    Essentially a proxy that will delay the connection to the first call.
    """

    def __init__(self):
        self.db = None
        self.collections = dict()
        self.graphs = dict()

    def connect(
        self,
        host: str = None,
        port: int = None,
        username: str = None,
        password: str = None,
        database: str = None,
        check_db_sync: bool = False,
    ):
        host = host or yeti_config.get("arangodb", "host")
        port = port or yeti_config.get("arangodb", "port")
        username = username or yeti_config.get("arangodb", "username")
        password = password or yeti_config.get("arangodb", "password")
        database = database or yeti_config.get("arangodb", "database")

        if TESTING:
            database = "yeti_test"

        host_string = f"http://{host}:{port}"
        client = ArangoClient(hosts=host_string, request_timeout=None)

        sys_db = client.db("_system", username=username, password=password)
        for _ in range(0, 4):
            try:
                yeti_db = sys_db.has_database(database)
                break
            except requests.exceptions.ConnectionError as e:
                logging.error("Connection error: {0:s}".format(str(e)))
                logging.error("Retrying in 5 seconds...")
                time.sleep(5)
        else:
            logging.error("Could not connect, bailing.")
            sys.exit(1)

        if not yeti_db:
            sys_db.create_database(database)

        self.db = client.db(database, username=username, password=password)
        if check_db_sync:
            self.check_database_version()

        self.create_edge_definition(
            self.graph("tags"),
            {
                "edge_collection": "tagged",
                "from_vertex_collections": ["observables", "entities", "indicators"],
                "to_vertex_collections": ["tags"],
            },
        )
        self.create_edge_definition(
            self.graph("threat_graph"),
            {
                "edge_collection": "links",
                "from_vertex_collections": [
                    "observables",
                    "entities",
                    "indicators",
                    "dfiq",
                ],
                "to_vertex_collections": [
                    "observables",
                    "entities",
                    "indicators",
                    "dfiq",
                ],
            },
        )

        self.create_indexes()
        self.create_analyzers()
        self.create_views()

    def check_database_version(self, skip_if_testing: bool = True):
        if TESTING and skip_if_testing:
            return
        system = list(self.db.collection("system").all())
        if not system:
            raise RuntimeError("Database version not found, please run migrations.")
        if system[0]["db_version"] != CODE_DB_VERSION:
            raise RuntimeError(
                f"Database version mismatch. Expected {CODE_DB_VERSION}, got {system[0]['db_version']}"
            )

    def create_analyzers(self):
        self.db.create_analyzer(
            name="norm",
            analyzer_type="norm",
            properties={"locale": "en", "accent": False, "case": "lower"},
            features=[],
        )

    def refresh_views(self):
        for view in self.db.views():
            self.db.update_view(
                name=view["name"],
                properties={"consolidationIntervalMsec": 0, "commitIntervalMsec": 0},
            )

    def create_indexes(self):
        self.db.collection("observables").add_persistent_index(
            fields=["value", "type"], unique=True, in_background=True, name="obs_index"
        )
        self.db.collection("observables").add_persistent_index(
            fields=["created"], in_background=True, name="obs_created_index"
        )

        self.db.collection("entities").add_persistent_index(
            fields=["name", "type"], unique=True, in_background=True, name="ent_index"
        )
        self.db.collection("entities").add_persistent_index(
            fields=["created"], in_background=True, name="ent_created_index"
        )

        self.db.collection("tags").add_persistent_index(
            fields=["name"], unique=True, in_background=True, name="tag_index"
        )
        self.db.collection("indicators").add_persistent_index(
            fields=["name", "type"], unique=True, in_background=True, name="ind_index"
        )
        self.db.collection("indicators").add_persistent_index(
            fields=["created"], in_background=True, name="ind_created_index"
        )
        self.db.collection("dfiq").add_persistent_index(
            fields=["uuid"],
            unique=True,
            sparse=True,
            in_background=True,
            name="dfiq_index",
        )
        self.db.collection("dfiq").add_persistent_index(
            fields=["created"], in_background=True, name="dfiq_created_index"
        )

    def create_views(self):
        for view_target in ("observables", "entities", "indicators", "dfiq"):
            try:
                if TESTING:
                    self.db.delete_view(f"{view_target}_view")
                else:
                    self.db.view(f"{view_target}_view")
                    continue
            except Exception:
                pass

            self.db.create_arangosearch_view(
                name=f"{view_target}_view",
                properties={
                    "consolidationIntervalMsec": 1 if TESTING else 1000,
                    "commitIntervalMsec": 1 if TESTING else 1000,
                    "links": {
                        view_target: {
                            "analyzers": ["identity", "norm"],
                            "fields": {},
                            "includeAllFields": True,
                            "storeValues": "none",
                            "trackListPositions": False,
                        }
                    },
                    "primarySort": [
                        {"field": "created", "direction": "desc"},
                        {"field": "value", "direction": "asc"},
                        {"field": "name", "direction": "asc"},
                    ],
                },
            )

    def truncate(self, collection_name=None):
        if collection_name:
            collection = self.db.collection(collection_name)
            collection.truncate()
            return
        for collection_data in self.db.collections():
            if collection_data["system"]:
                continue
            collection = self.db.collection(collection_data["name"])
            collection.truncate()

    def clear(self, truncate=True):
        if not self.db:
            self.connect()
        for collection_data in self.db.collections():
            if collection_data["system"]:
                continue
            if truncate:
                collection = self.db.collection(collection_data["name"])
                collection.truncate()
            else:
                self.db.delete_collection(collection_data["name"])
        self.collections = {}

    def collection(self, name):
        if self.db is None:
            self.connect()
        if name not in self.collections:
            async_db = self.db.begin_async_execution(return_result=True)
            job = async_db.has_collection(name)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            data = job.result()
            if data:
                self.collections[name] = async_db.collection(name)
            else:
                job = async_db.create_collection(name)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                self.collections[name] = job.result()
        return self.collections[name]

    def graph(self, name):
        if self.db is None:
            self.connect()
        if name not in self.graphs:
            async_db = self.db.begin_async_execution(return_result=True)
            job = async_db.has_graph(name)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            data = job.result()
            if data:
                graph = async_db.graph(name)
                self.graphs[name] = graph
            else:
                job = async_db.create_graph(name)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                self.graphs[name] = job.result()
        return self.graphs[name]

    # graph is in async context
    def create_edge_definition(self, graph, definition):
        if self.db is None:
            self.connect()

        if not self.db.has_collection(definition["edge_collection"]):
            job = graph.create_edge_definition(**definition)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            collection = job.result()
        else:
            job = graph.replace_edge_definition(**definition)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            collection = job.result()
        self.collections[definition["edge_collection"]] = collection
        return collection

    def __getattr__(self, key):
        if self.db is None and not key.startswith("__"):
            self.connect()
        return getattr(self.db, key)


db = ArangoDatabase()


class ArangoYetiConnector(AbstractYetiConnector):
    """Yeti connector for an ArangoDB backend."""

    _db = db

    def __init__(self):
        self._arango_id = None

    @property
    def extended_id(self):
        return self._collection_name + "/" + self.id

    def _insert(self, document_json: str):
        newdoc = None
        try:
            async_col = self._db.collection(self._collection_name)
            job = async_col.insert(json.loads(document_json), return_new=True)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            newdoc = job.result()
            newdoc = newdoc["new"]
        except DocumentInsertError as err:
            if not err.error_code == 1210:  # Unique constraint violation
                raise
            return None
        if not newdoc:
            return None
        newdoc["__id"] = newdoc.pop("_key")
        return newdoc

    def _update(self, document_json):
        #        document = self._db.update(self._collection_name, document_json)
        document = json.loads(document_json)
        doc_id = document.pop("id")
        async_col = self._db.collection(self._collection_name)
        newdoc = None
        if doc_id:
            document["_key"] = doc_id
            job = async_col.update(document, return_new=True)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            newdoc = job.result()
            newdoc = newdoc["new"]
        else:
            if "value" in document:
                filters = {"value": document["value"]}
            else:
                filters = {"name": document["name"]}
            if "type" in document:
                filters["type"] = document["type"]
            logging.debug(f"filters: {filters}")
            job = async_col.update_match(filters, document)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            try:
                job = async_col.find(filters, limit=1)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                result = job.result()
                newdoc = list(result)[0]
            except IndexError as exception:
                msg = f"Update failed when adding {document_json}: {exception}"
                logging.error(msg)
                raise RuntimeError(msg)

        if not newdoc:
            return None
        newdoc["__id"] = newdoc.pop("_key")
        return newdoc

    def save(
        self: TYetiObject, exclude_overwrite: list[str] = ["created", "tags", "context"]
    ) -> TYetiObject:
        """Inserts or updates a Yeti object into the database.

        We need to pass the JSON representation of the object to the database
        because it may contain fields that are not JSON serializable by arango.

        Args:
          exclude_overwrite: Exclude overwriting these fields if observable
            already exists in the database.

        Returns:
          The created Yeti object.
        """
        exclude = ["tags"] + self._exclude_overwrite
        doc_dict = self.model_dump(exclude_unset=True, exclude=exclude)
        if doc_dict.get("id") is not None:
            exclude = ["tags"] + self._exclude_overwrite
            result = self._update(self.model_dump_json(exclude=exclude))
            event_type = message.EventType.update
        else:
            exclude = ["tags", "id"] + self._exclude_overwrite
            result = self._insert(self.model_dump_json(exclude=exclude))
            event_type = message.EventType.new
            if not result:
                exclude = exclude_overwrite + self._exclude_overwrite
                result = self._update(self.model_dump_json(exclude=exclude))
                event_type = message.EventType.update
        yeti_object = self.__class__(**result)
        # TODO: Override this if we decide to implement YetiTagModel
        if hasattr(self, "tags"):
            yeti_object.get_tags()
        if self._collection_name != "auditlog":
            try:
                event = message.ObjectEvent(type=event_type, yeti_object=yeti_object)
                producer.publish_event(event)
            except Exception:
                logging.exception("Error while publishing event")
        return yeti_object

    @classmethod
    def list(cls: Type[TYetiObject]) -> Iterable[TYetiObject]:
        """Lists all objects.

        Returns:
          A list of YetiObjects.
        """
        coll = cls._collection_name
        type_filter = cls._type_filter

        if type_filter:
            objects = cls._db.aql.execute(
                "FOR o IN @@collection FILTER o.type IN @type RETURN o",
                bind_vars={"type": [type_filter], "@collection": coll},
            )
        else:
            objects = cls._db.aql.execute(
                "FOR o IN @@collection RETURN o", bind_vars={"@collection": coll}
            )

        for object in list(objects):
            object["__id"] = object.pop("_key")
            yield cls.load(object)

    @classmethod
    def get(cls: Type[TYetiObject], id: str) -> TYetiObject | None:
        """Fetches a single object by key.

        Args:
          id: ArangoDB _key value

        Returns:
          A Yeti object."""
        async_col = cls._db.collection(cls._collection_name)
        job = async_col.get(id)
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        document = job.result()
        if not document:
            return None
        document["__id"] = document.pop("_key")
        return cls.load(document)

    @classmethod
    def find(cls: Type[TYetiObject], **kwargs) -> TYetiObject | None:
        """Fetches a single object by value.

        Args:
          **kwargs: Keyword arguments that will be matched to the document.

        Returns:
          A Yeti object.
        """
        if "type" not in kwargs and getattr(cls, "_type_filter", None):
            kwargs["type"] = cls._type_filter

        async_col = cls._db.collection(cls._collection_name)
        job = async_col.find(kwargs, limit=1)
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        documents = job.result()
        if not documents:
            return None
        document = documents.pop()
        document["__id"] = document.pop("_key")
        return cls.load(document)

    def tag(
        self: TYetiObject,
        tags: List[str],
        strict: bool = False,
        normalized: bool = True,
        expiration: datetime.timedelta | None = None,
    ) -> TYetiObject:
        """Connects object to tag graph."""
        # Import at runtime to avoid circular dependency.
        from core.schemas import tag

        if self.id is None:
            raise RuntimeError(
                "Cannot tag unsaved object, make sure to save() it first."
            )

        if not isinstance(tags, (list, set, tuple)):
            raise ValueError("Tags must be of type list, set or tuple.")

        tags = [t.strip() for t in tags if t.strip()]
        if strict:
            self.clear_tags()

        extra_tags = set()
        for provided_tag_name in tags:
            tag_name = tag.normalize_name(provided_tag_name)
            if not tag_name:
                raise RuntimeError(
                    f"Cannot tag object with empty tag: '{provided_tag_name}' -> '{tag_name}'"
                )
            replacements, _ = tag.Tag.filter({"in__replaces": [tag_name]}, count=1)
            new_tag: Optional[tag.Tag] = None

            if replacements:
                new_tag = replacements[0]
            # Attempt to find actual tag
            else:
                new_tag = tag.Tag.find(name=tag_name)
            # Create tag
            if not new_tag:
                new_tag = tag.Tag(name=tag_name).save()

            expiration = expiration or new_tag.default_expiration
            tag_link = self.link_to_tag(new_tag.name, expiration=expiration)
            self._tags[new_tag.name] = tag_link

            extra_tags |= set(new_tag.produces)

        extra_tags -= set(tags)
        if extra_tags:
            self.tag(list(extra_tags))

        return self

    def link_to_tag(
        self, tag_name: str, expiration: datetime.timedelta
    ) -> "TagRelationship":
        """Links a YetiObject to a Tag object.

        Args:
          tag_name: The name of the tag to link to.
        """
        # Import at runtime to avoid circular dependency.
        from core.schemas.graph import TagRelationship
        from core.schemas.tag import Tag

        graph = self._db.graph("tags")

        tags = self.get_tags()

        for tag_relationship, tag in tags:
            if tag.name != tag_name:
                continue
            tag_relationship.last_seen = datetime.datetime.now(datetime.timezone.utc)
            tag_relationship.fresh = True
            edge = json.loads(tag_relationship.model_dump_json())
            edge["_id"] = tag_relationship.id
            graph.update_edge(edge)
            if self._collection_name != "auditlog":
                try:
                    event = message.TagEvent(
                        type=message.EventType.update,
                        tagged_object=self,
                        tag_object=tag,
                    )
                    producer.publish_event(event)
                except Exception:
                    logging.exception("Error while publishing event")
            return tag_relationship

        # Relationship doesn't exist, check if tag is already in the db
        tag_obj = Tag.find(name=tag_name)
        if not tag_obj:
            tag_obj = Tag(name=tag_name).save()
        tag_obj.count += 1
        tag_obj.save()

        tag_relationship = TagRelationship(
            source=self.extended_id,
            target=tag_obj.extended_id,
            last_seen=datetime.datetime.now(datetime.timezone.utc),
            expires=datetime.datetime.now(datetime.timezone.utc) + expiration,
            fresh=True,
        )

        job = graph.edge_collection("tagged").link(
            self.extended_id,
            tag_obj.extended_id,
            data=json.loads(tag_relationship.model_dump_json()),
            return_new=True,
        )
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        result = job.result()["new"]
        result["__id"] = result.pop("_key")
        if self._collection_name != "auditlog":
            try:
                event = message.TagEvent(
                    type=message.EventType.new, tagged_object=self, tag_object=tag_obj
                )
                producer.publish_event(event)
            except Exception:
                logging.exception("Error while publishing event")
        return TagRelationship.load(result)

    def expire_tag(self, tag_name: str) -> "TagRelationship":
        """Expires a tag on an Observable.

        Args:
          tag_name: The name of the tag to expire.
        """
        # Avoid circular dependency
        graph = self._db.graph("tags")

        tags = self.get_tags()

        for tag_relationship, tag in tags:
            if tag.name != tag_name:
                continue
            tag_relationship.fresh = False
            edge = json.loads(tag_relationship.model_dump_json())
            edge["_id"] = tag_relationship.id
            graph.update_edge(edge)
            return tag_relationship

        raise ValueError(
            f"Tag '{tag_name}' not found on observable '{self.extended_id}'"
        )

    def clear_tags(self):
        """Clears all tags on an Observable."""
        # Avoid circular dependency
        graph = self._db.graph("tags")

        self.get_tags()
        job = graph.edge_collection("tagged").edges(self.extended_id)
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        results = job.result()
        for edge in results["edges"]:
            if self._collection_name != "auditlog":
                try:
                    job = self._db.collection("tagged").get(edge["_id"])
                    while job.status() != "done":
                        time.sleep(ASYNC_JOB_WAIT_TIME)
                    tag_relationship = job.result()
                    tag_collection, tag_id = tag_relationship["target"].split("/")
                    job = self._db.collection(tag_collection).get(tag_id)
                    while job.status() != "done":
                        time.sleep(ASYNC_JOB_WAIT_TIME)
                    tag_obj = job.result()
                    event = message.TagEvent(
                        type=message.EventType.delete,
                        tagged_object=self,
                        tag_object=tag_obj,
                    )
                    producer.publish_event(event)
                except Exception:
                    logging.exception("Error while publishing event")
            job = graph.edge_collection("tagged").delete(edge["_id"])
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)

    def link_to(
        self, target, relationship_type: str, description: str
    ) -> "Relationship":
        """Creates a link between two YetiObjects.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
          description: A description of the link.
        """
        # Avoid circular dependency
        from core.schemas.graph import Relationship

        async_graph = self._db.graph("threat_graph")

        # Check if a relationship with the same link_type already exists
        aql = """
        WITH observables

        FOR v, e, p IN 1..1 OUTBOUND @extended_id
        links
          FILTER e.type == @relationship_type
          FILTER v._id == @target_extended_id
        RETURN e"""
        args = {
            "extended_id": self.extended_id,
            "target_extended_id": target.extended_id,
            "relationship_type": relationship_type,
        }
        neighbors = list(self._db.aql.execute(aql, bind_vars=args))
        if neighbors:
            neighbors[0]["__id"] = neighbors[0].pop("_key")
            relationship = Relationship.load(neighbors[0])
            relationship.modified = datetime.datetime.now(datetime.timezone.utc)
            relationship.description = description
            relationship.count += 1
            edge = json.loads(relationship.model_dump_json())
            edge["_id"] = neighbors[0]["_id"]
            job = async_graph.update_edge(edge)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            if self._collection_name != "auditlog":
                try:
                    event = message.LinkEvent(
                        type=message.EventType.update,
                        source_object=self,
                        target_object=target,
                        relationship=relationship,
                    )
                    producer.publish_event(event)
                except Exception:
                    logging.exception("Error while publishing event")
            return relationship

        relationship = Relationship(
            type=relationship_type,
            source=self.extended_id,
            target=target.extended_id,
            count=1,
            description=description,
            created=datetime.datetime.now(datetime.timezone.utc),
            modified=datetime.datetime.now(datetime.timezone.utc),
        )
        col = async_graph.edge_collection("links")
        job = col.link(
            self.extended_id,
            target.extended_id,
            data=json.loads(relationship.model_dump_json()),
            return_new=True,
        )
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        result = job.result()["new"]
        result["__id"] = result.pop("_key")
        relationship = Relationship.load(result)
        if self._collection_name != "auditlog":
            try:
                event = message.LinkEvent(
                    type=message.EventType.new,
                    source_object=self,
                    target_object=target,
                    relationship=relationship,
                )
                producer.publish_event(event)
            except Exception:
                logging.exception("Error while publishing event")
        return relationship

    def swap_link(self):
        """Swaps the source and target of a relationship."""
        # Avoid circular dependency
        self.target, self.source = self.source, self.target
        edge = json.loads(self.model_dump_json())
        edge["_from"] = self.source
        edge["_to"] = self.target
        edge["_id"] = f"links/{self.id}"
        graph = self._db.graph("threat_graph")
        job = graph.update_edge(edge)
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        self.save()

    # TODO: Consider extracting this to its own class, given it's only meant
    # to be called by Observables.
    def get_tags(self) -> List[Tuple["TagRelationship", "Tag"]]:
        """Returns the tags linked to this object.

        Returns:
          A list of tuples (TagRelationship, Tag) representing each tag linked
          to this object.
        """
        from core.schemas.graph import TagRelationship
        from core.schemas.tag import Tag

        tag_aql = """
            for v, e, p IN 1..1 OUTBOUND @extended_id GRAPH tags
            OPTIONS {uniqueVertices: "path"}
            RETURN p
        """
        tag_paths = list(
            self._db.aql.execute(tag_aql, bind_vars={"extended_id": self.extended_id})
        )
        if not tag_paths:
            return []
        relationships = []
        for path in tag_paths:
            tag_data = Tag.load(path["vertices"][1])
            edge_data = path["edges"][0]
            edge_data["__id"] = edge_data.pop("_id")
            tag_relationship = TagRelationship.load(edge_data)
            relationships.append((tag_relationship, tag_data))
            self._tags[tag_data.name] = tag_relationship
        return relationships

    # pylint: disable=too-many-arguments
    def neighbors(
        self,
        link_types: List[str] = [],
        target_types: List[str] = [],
        direction: str = "any",
        graph: str = "links",
        filter: List["GraphFilter"] = [],
        include_original: bool = False,
        min_hops: int = 1,
        max_hops: int = 1,
        offset: int = 0,
        count: int = 0,
        sorting: List[tuple[str, bool]] = [],
    ) -> tuple[
        dict[
            str,
            "observable.ObservableTypes | entity.EntityTypes | indicator.IndicatorTypes | tag.Tag",
        ],
        List[List["Relationship | TagRelationship"]],
        int,
    ]:
        """Fetches neighbors of the YetiObject.

        Args:
          link_types: The types of link.
          target_types: The types of the target objects (as specified in the
              'type' field).
          direction: outbound, inbound, or any.
          include_original: Whether the original object is to be included in the
              result or not.
          min_hops: The minumum number of nodes to go through (defaults to 1:
              direct neighbors)
          max_hops: The maximum number of nodes to go through (defaults to 1:
              direct neighbors)
          raw: Whether to return a raw dictionary or a Yeti object.

        Returns:
          Tuple[dict, list, int]:
            - the neighbors (vertices),
            - the relationships (edges),
            - total neighbor (vertices) count
        """
        query_filter = ""
        args = {
            "extended_id": self.extended_id,
            "@graph": graph,
        }
        sorts = []
        for field, asc in sorting:
            sorts.append(f'p.edges[0].{field} {"ASC" if asc else "DESC"}')
        sorting_aql = f"SORT {', '.join(sorts)}" if sorts else ""

        if link_types:
            args["link_types"] = link_types
            query_filter = "FILTER e.type IN @link_types"
        if target_types:
            args["target_types"] = target_types
            query_filter = (
                "FILTER (v.type IN @target_types OR v.root_type IN @target_types)"
            )
        if filter:
            filters = []
            for i, f in enumerate(filter):
                if f.operator not in {"=~", "=", "in"}:
                    f.operator = "="

                if f.operator in {"=~", "="}:
                    filters.append(
                        f"(p.edges[*].@filter_key{i} {f.operator} @filter_value{i} OR p.vertices[*].@filter_key{i} {f.operator} @filter_value{i})"
                    )
                if f.operator == "in":
                    filters.append(
                        f"""COUNT(
                              FOR arr IN p.vertices[*].@filter_key{i}
                              FILTER COUNT(
                                FOR item in arr || []
                                FILTER REGEX_TEST(item, @filter_value{i}, true) RETURN arr
                              ) > 0
                              RETURN arr
                            ) > 0"""
                    )
                args[f"filter_key{i}"] = f.key
                args[f"filter_value{i}"] = f.value
            query_filter += f"FILTER {' OR '.join(filters)}"

        limit = ""
        if count != 0:
            limit += "LIMIT @offset, @count"
            args["offset"] = offset
            args["count"] = count

        args["min_hops"] = min_hops
        args["max_hops"] = max_hops
        if direction not in {"any", "inbound", "outbound"}:
            direction = "any"

        aql = f"""
        WITH tags, observables, entities, dfiq, indicators

        FOR v, e, p IN @min_hops..@max_hops {direction} @extended_id @@graph
          OPTIONS {{ uniqueVertices: "path" }}
          {query_filter}
          LET v_with_tags = (
            FOR observable in p['vertices']
              let innertags = (FOR tag, edge in 1..1 OUTBOUND observable tagged RETURN {{ [tag.name]: edge }})
              RETURN MERGE(observable, {{tags: MERGE(innertags)}})
          )
          {limit}
          {sorting_aql}
          RETURN {{ vertices: v_with_tags, g: p }}
        """
        cursor = self._db.aql.execute(aql, bind_vars=args, count=True, full_count=True)
        total = cursor.statistics().get("fullCount", count)
        paths = []  # type: list[list[Relationship]]
        vertices = {}  # type: dict[str, ArangoYetiConnector]
        neighbors = list(cursor)
        for path in neighbors:
            paths.append(self._build_edges(path["g"]["edges"]))
            self._build_vertices(vertices, path["vertices"])
        if not include_original:
            vertices.pop(self.extended_id, None)
        return vertices, paths, total or 0

    def _dedup_edges(self, edges):
        """Deduplicates edges with same STIX ID, keeping the most recent one.

        Args:
          edges: list of JSON-serialized STIX2 SROs.

        Returns:
          A list of the most recent versions of JSON-serialized STIX2 SROs.
        """
        seen = {}
        for edge in edges:
            seen[edge.id] = edge
        return list(seen.values())

    def _build_edges(self, arango_edges) -> List["RelationshipTypes"]:
        # Avoid circular dependency
        from core.schemas import graph

        relationships = []
        for edge in arango_edges:
            edge["__id"] = edge.pop("_key")
            edge["source"] = edge.pop("_from")
            edge["target"] = edge.pop("_to")
            if "tagged" in edge["_id"]:
                relationships.append(graph.TagRelationship.load(edge))
            else:
                relationships.append(graph.Relationship.load(edge))
        return relationships

    def _build_vertices(self, vertices, arango_vertices):
        # Import happens here to avoid circular dependency
        from core.schemas import dfiq, entity, indicator, observable, tag

        type_mapping = {
            "tag": tag.Tag,
        }
        type_mapping.update(observable.TYPE_MAPPING)
        type_mapping.update(entity.TYPE_MAPPING)
        type_mapping.update(indicator.TYPE_MAPPING)
        type_mapping.update(dfiq.TYPE_MAPPING)

        for vertex in arango_vertices:
            if vertex["_key"] in vertices:
                continue
            neighbor_schema = type_mapping[vertex.get("type", "tag")]
            vertex["__id"] = vertex.pop("_key")
            # We want the "extended ID" here, e.g. observables/12345
            vertices[vertex["_id"]] = neighbor_schema.load(vertex)

    @classmethod
    def filter(
        cls: Type[TYetiObject],
        query_args: dict[str, Any],
        tag_filter: List[str] = [],
        offset: int = 0,
        count: int = 0,
        sorting: List[tuple[str, bool]] = [],
        aliases: List[tuple[str, str]] = [],
        graph_queries: List[tuple[str, str, str, str]] = [],
        links_count: bool = False,
        wildcard: bool = True,
    ) -> tuple[List[TYetiObject], int]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            query_args: A key:value dictionary containing keys to filter objects
                on.
            tag_filter: A list of tags to filter on.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.
            sorting: A list of (order, ascending) fields to sort by.
            graph_queries: A list of (name, graph, direction, field) tuples to
                query the graph with.
            wildcard: whether all values should be interpreted as wildcard searches.

        Returns:
            A List of Yeti objects, and the total object count.
        """
        cls._get_collection()
        colname = cls._collection_name
        conditions = []
        filter_conditions = []  # used for clauses that are not supported by arangosearch
        sorts = []

        using_view = False
        if (
            query_args
            and colname in ("observables", "entities", "indicators", "dfiq")
            and wildcard
            # and not any([key.endswith("~") for key in query_args])
        ):
            using_view = True
            colname += "_view"

        # We want user-defined sorts to take precedence.
        links_count_query = ""
        if links_count:
            links_count_query = """
            LET aggregated_links = MERGE(
                FOR v, e IN 1..1 ANY o links COLLECT root_type = v.root_type INTO vtypes = {'type': v.type}
                LET sub_types = MERGE(FOR vt IN vtypes COLLECT vtype = vt.type WITH COUNT INTO type_count RETURN {[vtype]: type_count})
                LET details = MERGE(sub_types, {'total': SUM(VALUES(sub_types))})
                RETURN {[root_type]: details}
            )
            LET total_links = SUM(FOR k IN ATTRIBUTES(aggregated_links) RETURN aggregated_links[k].total)
            """

        for field, asc in sorting:
            if field == "total_links" and links_count:
                sorts.append(f'total_links {"ASC" if asc else "DESC"}')
            else:
                sorts.append(f'o.{field} {"ASC" if asc else "DESC"}')

        aql_args: dict[str, str | int | list] = {}
        for i, (key, value) in enumerate(list(query_args.items())):
            if key.endswith("~"):
                using_regex = True
                key = key[:-1]
            else:
                using_regex = False
            if isinstance(value, str):
                aql_args[f"arg{i}_value"] = value
            elif isinstance(value, list):
                aql_args[f"arg{i}_value"] = [v.strip() for v in value]

            if key.startswith("in__"):
                if using_view:
                    conditions.append(f"o.@arg{i}_key IN @arg{i}_value")
                else:
                    conditions.append(f"o.@arg{i}_key IN [@arg{i}_value]")
                aql_args[f"arg{i}_key"] = key[4:]
            elif key.endswith("__in"):  # o.value is in [1, 2, 3]
                conditions.append(f"o.@arg{i}_key IN @arg{i}_value")
                aql_args[f"arg{i}_key"] = key[:-4]
            elif key in {"labels", "relevant_tags"}:
                conditions.append(f"o.@arg{i}_key IN @arg{i}_value")
                aql_args[f"arg{i}_key"] = key
            elif key in ("created", "expires"):
                operator = value[0]
                if operator not in ["<", ">"]:
                    operator = "="
                else:
                    aql_args[f"arg{i}_value"] = value[1:]
                filter_conditions.append(
                    f"DATE_TIMESTAMP(o.{key}) {operator}= DATE_TIMESTAMP(@arg{i}_value)"
                )
                sorts.append(f"o.{key}")
            elif key in ("name", "value"):
                if using_view and not using_regex:
                    aql_args[f"arg{i}_value"] = f"%{value}%"
                    key_conditions = [
                        f"ANALYZER(LIKE(o.@arg{i}_key, LOWER(@arg{i}_value)), 'norm')"
                    ]
                else:
                    key_conditions = [f"REGEX_TEST(o.@arg{i}_key, @arg{i}_value, true)"]

                for alias, alias_type in aliases:
                    if (
                        alias_type in {"text", "option"}
                        or alias_type == "list"
                        and using_view
                    ):
                        if using_view and not using_regex:
                            key_conditions.append(
                                f"ANALYZER(LIKE(o.{alias}, LOWER(@arg{i}_value)), 'norm')"
                            )
                        else:
                            key_conditions.append(
                                f"REGEX_TEST(o.{alias}, @arg{i}_value, true)"
                            )
                    elif alias_type == "list":
                        if using_regex:
                            key_conditions.append(
                                f"COUNT(FOR i IN o.{alias} || [] FILTER REGEX_TEST(i, @arg{i}_value, true) RETURN i) > 0"
                            )
                        else:
                            key_conditions.append(
                                f"COUNT(FOR i IN o.{alias} || [] FILTER LIKE(i, @arg{i}_value) RETURN i) > 0"
                            )
                key_condition = " OR ".join(key_conditions)
                if using_regex:
                    filter_conditions.append(f"({key_condition})")
                else:
                    conditions.append(f"({key_condition})")
                aql_args[f"arg{i}_key"] = key
            else:
                aql_args[f"arg{i}_key"] = key
                if using_regex:
                    filter_conditions.append(
                        f"REGEX_TEST(o.@arg{i}_key, @arg{i}_value, true)"
                    )
                else:
                    aql_args[f"arg{i}_value"] = f"%{value}%"
                    conditions.append(f"LIKE(o.@arg{i}_key, @arg{i}_value)")

        limit = ""
        if count != 0:
            limit = "LIMIT @offset, @count"
            aql_args["offset"] = offset
            aql_args["count"] = count

        # TODO: Interpolate this query
        graph_query_string = ""
        for name, graph, direction, field in graph_queries:
            graph_query_string += f"\nLET {name} = (FOR v, e in 1..1 {direction} o {graph} RETURN {{ [v.{field}]: e }})"

        tag_filter_query = ""
        if tag_filter:
            tag_filter_query = (
                " FILTER COUNT(INTERSECTION(ATTRIBUTES(MERGE(tags)), @tag_names)) > 0"
            )
            aql_args["tag_names"] = tag_filter

        filter_string = ""
        if filter_conditions:
            filter_string = f"FILTER {' AND '.join(filter_conditions)}"

        aql_search = ""
        if conditions:
            aql_search = (
                f"{'SEARCH' if using_view else 'FILTER'} {' AND '.join(conditions)}"
            )

        aql_sort = ""
        if sorts:
            aql_sort = f"SORT {', '.join(sorts)}"

        aql_string = f"""
            FOR o IN @@collection
                {aql_search}
                {links_count_query}
                {graph_query_string}
                {tag_filter_query}
                {filter_string}
                {aql_sort}
                {limit}
            """
        merged_list = ""
        prologue = ""
        if graph_queries:
            merged_list = ", ".join(
                [f"{name}: MERGE({name})" for name, _, _, _ in graph_queries]
            )
            prologue = "WITH " + ", ".join([name for name, _, _, _ in graph_queries])
        if links_count:
            merged_list += (
                ", aggregated_links, total_links"
                if merged_list
                else "aggregated_links, total_links"
            )
        if merged_list:
            aql_string = (
                f"{prologue}\n\n{aql_string}\nRETURN MERGE(o, {{ {merged_list} }})"
            )
        else:
            aql_string += "\nRETURN o"
        aql_args["@collection"] = colname
        logging.debug(f"aql_string: {aql_string}, aql_args: {aql_args}")
        documents = cls._db.aql.execute(
            aql_string, bind_vars=aql_args, count=True, full_count=True
        )
        stats = documents.statistics()
        results = []
        for doc in documents:
            doc["__id"] = doc.pop("_key")
            results.append(cls.load(doc))
        total = stats.get("fullCount", len(results))
        return results, total or 0

    @classmethod
    def fulltext_filter(cls, keywords):
        """Search in an ArangoDB collection using full-text search.

        Args:
          query: Keywords to use in the full-text query.

        Returns:
          A List of Yeti objects.
        """
        collection = cls._get_collection()
        query = ",".join(keywords)
        yeti_objects = []
        key = cls._text_indexes[0]["fields"][0]
        for document in collection.find_by_text(key, query):
            document["__id"] = document.pop("_key")
            yeti_objects.append(cls.load(document, strict=True))
        return yeti_objects

    def delete(self, all_versions=True):
        """Deletes an object from the database."""
        job = self._db.graph("threat_graph").has_vertex_collection(
            self._collection_name
        )
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        if job.result():
            col = self._db.graph("threat_graph").vertex_collection(
                self._collection_name
            )
        else:
            col = self._db.collection(self._collection_name)
        job = col.delete(self.id)
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        if self._collection_name == "auditlog":
            return
        try:
            event_type = message.EventType.delete
            if self._collection_name == "tagged":
                source_collection, source_id = self.source.split("/")
                tag_collection, tag_id = self.target.split("/")
                job = self._db.collection(source_collection).get(source_id)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                source_obj = job.result()
                job = self._db.collection(tag_collection).get(tag_id)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                tag_obj = job.result()
                event = message.TagEvent(
                    type=event_type, tagged_object=source_obj, tag_object=tag_obj
                )
            elif self._collection_name == "links":
                source_collection, source_id = self.source.split("/")
                target_collection, target_id = self.target.split("/")
                job = self._db.collection(source_collection).get(source_id)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                source_obj = job.result()
                job = self._db.collection(target_collection).get(target_id)
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                target_obj = job.result()
                event = message.LinkEvent(
                    type=event_type,
                    source_object=source_obj,
                    target_object=target_obj,
                    relationship=self,
                )
            else:
                event = message.ObjectEvent(type=event_type, yeti_object=self)
            producer.publish_event(event)
        except Exception:
            logging.exception("Error while publishing event")

    @classmethod
    def _get_collection(cls):
        """Get the collection corresponding to this Yeti object class.

        Ensures the collection is properly indexed.

        Returns:
          The ArangoDB collection corresponding to the object class.
        """
        return cls._db.collection(cls._collection_name)


def tagged_observables_export(cls, args):
    aql = """
        WITH tags

        FOR o in observables
        FILTER (o.type IN @acts_on OR @acts_on == [])
        LET tags = MERGE(
                FOR v, e in 1..1 OUTBOUND o tagged
                    FILTER v.name NOT IN @ignore
                    FILTER (e.fresh OR NOT @fresh)
                RETURN {[v.name]: MERGE(e, {id: e._id})}
        )
        FILTER tags != {}
        LET tagnames = ATTRIBUTES(tags)

        FILTER COUNT(INTERSECTION(tagnames, @include)) > 0 OR @include == []
        FILTER COUNT(INTERSECTION(tagnames, @exclude)) == 0
        RETURN MERGE(o, {tags: tags})
        """
    documents = db.aql.execute(aql, bind_vars=args, count=True, full_count=True)
    results = []
    for doc in documents:
        doc["__id"] = doc.pop("_key")
        results.append(cls.load(doc))
    return results
