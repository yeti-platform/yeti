"""Class implementing a YetiConnector interface for ArangoDB."""

import datetime
import json
import logging
import sys
import time
from typing import TYPE_CHECKING, Any, Iterable, List, Optional, Type, TypeVar

if TYPE_CHECKING:
    from core.schemas import dfiq, entity, indicator, observable, rbac, roles, tag, user
    from core.schemas.graph import (
        GraphFilter,
        Relationship,
        RelationshipTypes,
        RoleRelationship,
    )


import requests
from arango import ArangoClient
from arango.exceptions import DocumentInsertError

from core.config.config import yeti_config
from core.events import message
from core.events.producer import producer

from .interfaces import AbstractYetiConnector

CODE_DB_VERSION = 2
AQL_QUERY_MAX_TTL = 3600 * 12

LINK_TYPE_TO_GRAPH = {
    "tagged": "tags",
    "stix": "stix",
}

TESTING = "unittest" in sys.modules.keys()

ASYNC_JOB_WAIT_TIME = 0.01

RBAC_ENABLED = yeti_config.get("rbac", "enabled", default=False)

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

        self.create_collections()
        self.create_graphs()
        self.create_indexes()
        self.create_analyzers()
        self.create_views()

    def create_collections(self):
        """Creates the collections in the database."""
        collections = [
            "auditlog",
            "dfiq",
            "entities",
            "groups",
            "indicators",
            "observables",
            "system",
            "tags",
            "tasks",
            "timeline",
            "users",
        ]
        for collection in collections:
            if not self.db.has_collection(collection):
                self.db.create_collection(collection)

    def create_graphs(self):
        """Creates the graphs in the database."""
        if not self.db.has_graph("threat_graph"):
            self.db.create_graph(
                "threat_graph",
                edge_definitions=[
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
                    }
                ],
            )
        if not self.db.has_graph("systemroles"):
            self.db.create_graph(
                "systemroles",
                edge_definitions=[
                    {
                        "edge_collection": "acls",
                        "from_vertex_collections": ["users", "groups"],
                        "to_vertex_collections": [
                            "groups",
                            "observables",
                            "entities",
                            "indicators",
                            "dfiq",
                        ],
                    }
                ],
            )

    def check_database_version(self, skip_if_testing: bool = True):
        if TESTING and skip_if_testing:
            return
        system = self.db.collection("system").all()
        if system.empty():
            raise RuntimeError("Database version not found, please run migrations.")
        entry = system.pop()
        if "db_version" not in entry:
            raise RuntimeError("Database version not found, please run migrations.")
        if entry["db_version"] != CODE_DB_VERSION:
            raise RuntimeError(
                f"Database version mismatch. Expected {CODE_DB_VERSION}, got {entry['db_version']}"
            )

    def create_analyzers(self):
        self.db.create_analyzer(
            name="norm",
            analyzer_type="norm",
            properties={"locale": "en.utf-8", "accent": False, "case": "lower"},
        )

    def refresh_views(self):
        for view in self.db.views():
            self.db.update_view(
                name=view["name"],
                properties={"consolidationIntervalMsec": 0, "commitIntervalMsec": 0},
            )

    def create_indexes(self):
        self.db.collection("observables").add_index(
            {
                "fields": ["value", "type"],
                "unique": True,
                "in_background": True,
                "name": "obs_index",
                "type": "persistent",
            }
        )
        self.db.collection("observables").add_index(
            {
                "fields": ["created"],
                "in_background": True,
                "name": "obs_created_index",
                "type": "persistent",
            }
        )

        self.db.collection("entities").add_index(
            {
                "fields": ["name", "type"],
                "unique": True,
                "in_background": True,
                "name": "ent_index",
                "type": "persistent",
            }
        )
        self.db.collection("entities").add_index(
            {
                "fields": ["created"],
                "in_background": True,
                "name": "ent_created_index",
                "type": "persistent",
            }
        )

        self.db.collection("tags").add_index(
            {
                "fields": ["name"],
                "unique": True,
                "in_background": True,
                "name": "tag_index",
                "type": "persistent",
            }
        )
        self.db.collection("indicators").add_index(
            {
                "fields": ["name", "type"],
                "unique": True,
                "in_background": True,
                "name": "ind_index",
                "type": "persistent",
            }
        )
        self.db.collection("indicators").add_index(
            {
                "fields": ["created"],
                "in_background": True,
                "name": "ind_created_index",
                "type": "persistent",
            }
        )
        self.db.collection("dfiq").add_index(
            {
                "fields": ["uuid"],
                "unique": True,
                "sparse": True,
                "in_background": True,
                "name": "dfiq_index",
                "type": "persistent",
            }
        )
        self.db.collection("dfiq").add_index(
            {
                "fields": ["created"],
                "in_background": True,
                "name": "dfiq_created_index",
                "type": "persistent",
            }
        )
        self.db.collection("groups").add_index(
            {
                "fields": ["name"],
                "unique": True,
                "in_background": True,
                "name": "group_name_index",
                "type": "persistent",
            }
        )
        self.db.collection("users").add_index(
            {
                "fields": ["username"],
                "unique": True,
                "in_background": True,
                "name": "user_name_index",
                "type": "persistent",
            }
        )

    def create_views(self):
        link_definitions = {}
        for view_target in ("observables", "entities", "indicators", "dfiq"):
            try:
                if TESTING:
                    self.db.delete_view(f"{view_target}_view")
                else:
                    self.db.view(f"{view_target}_view")
                    continue
            except Exception:
                pass

            link_definitions[view_target] = {
                "analyzers": ["identity", "norm"],
                "includeAllFields": True,
                "trackListPositions": False,
            }

            self.db.create_arangosearch_view(
                name=f"{view_target}_view",
                properties={
                    "consolidationIntervalMsec": 1 if TESTING else 1000,
                    "commitIntervalMsec": 1 if TESTING else 1000,
                    "links": {view_target: link_definitions[view_target]},
                    "primarySort": [
                        {"field": "created", "direction": "desc"},
                        {"field": "value", "direction": "asc"},
                        {"field": "name", "direction": "asc"},
                    ],
                },
            )

        try:
            if TESTING:
                self.db.delete_view("all_objects_view")
            else:
                self.db.view("all_objects_view")
                return
        except Exception:
            pass

        for target in link_definitions:
            del link_definitions[target]["analyzers"]
            link_definitions[target]["analyzers"] = []
            link_definitions[target]["includeAllFields"] = False
            link_definitions[target]["fields"] = {
                "tags": {"fields": {"name": {"analyzers": ["identity", "norm"]}}},
                "dfiq_tags": {"analyzers": ["identity", "norm"]},
                "type": {"analyzers": ["identity", "norm"]},
                "root_type": {"analyzers": ["identity", "norm"]},
                "value": {"analyzers": ["identity", "norm"]},
                "name": {"analyzers": ["identity", "norm"]},
                "created": {"analyzers": ["identity", "norm"]},
            }

        self.db.create_arangosearch_view(
            name="all_objects_view",
            properties={
                "consolidationIntervalMsec": 1 if TESTING else 1000,
                "commitIntervalMsec": 1 if TESTING else 1000,
                "links": link_definitions,
                "primarySort": [
                    {"field": "created", "direction": "desc"},
                    {"field": "value", "direction": "asc"},
                    {"field": "name", "direction": "asc"},
                    {"field": "tags.name", "direction": "asc"},
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
    _collection_name: str | None = None

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
            if self._collection_name in ("acls", "links"):
                job = async_col.update(document, return_new=True)
            else:
                job = async_col.update(document, return_new=True, merge=False)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            newdoc = job.result()
            newdoc = newdoc["new"]
        else:
            if self._collection_name == "observables":
                filters = {"value": document["value"]}
            elif self._collection_name in ("users"):
                filters = {"username": document["username"]}
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
                newdoc = result.pop()
            except IndexError as exception:
                msg = f"Update failed when adding {document_json}: {exception}"
                logging.error(msg)
                raise RuntimeError(msg)

        if not newdoc:
            return None
        newdoc["__id"] = newdoc.pop("_key")
        return newdoc

    def save(
        self: TYetiObject,
        exclude_overwrite: list[str] = ["created", "tags", "context", "acls"],
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
        exclude = self._exclude_overwrite
        doc_dict = self.model_dump(exclude_unset=True, exclude=exclude)
        if doc_dict.get("id") is not None:
            exclude = ["acls"] + self._exclude_overwrite
            result = self._update(self.model_dump_json(exclude=exclude))
            event_type = message.EventType.update
        else:
            exclude = ["acls", "id"] + self._exclude_overwrite
            result = self._insert(self.model_dump_json(exclude=exclude))
            event_type = message.EventType.new
            if not result:
                exclude = exclude_overwrite + self._exclude_overwrite
                result = self._update(self.model_dump_json(exclude=exclude))
                event_type = message.EventType.update
        yeti_object = self.__class__(**result)
        if self._collection_name not in ("auditlog", "timeline"):
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
                ttl=AQL_QUERY_MAX_TTL,
            )
        else:
            objects = cls._db.aql.execute(
                "FOR o IN @@collection RETURN o",
                bind_vars={"@collection": coll},
                ttl=AQL_QUERY_MAX_TTL,
            )

        for object in objects:
            try:
                object["__id"] = object.pop("_key")
                instance = cls.load(object)
                yield instance
            except Exception:
                logging.exception(f"Can't load object {object}")

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
        neighbors = self._db.aql.execute(aql, bind_vars=args)
        if not neighbors.empty():
            neighbor = neighbors.pop()
            neighbor["__id"] = neighbor.pop("_key")
            relationship = Relationship.load(neighbor)
            relationship.modified = datetime.datetime.now(datetime.timezone.utc)
            relationship.description = description
            relationship.count += 1
            edge = json.loads(relationship.model_dump_json())
            edge["_id"] = neighbor["_id"]
            job = async_graph.update_edge(edge)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            if self._collection_name not in ("auditlog", "timeline"):
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
        if self._collection_name not in ("auditlog", "timeline"):
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

    def link_to_acl(self, target, role: "roles.Permission") -> "RoleRelationship":
        """Creates a link between two YetiObjects.

        Args:
          target: The YetiObject to link to.
          role: The role to assign to the target.
        """
        # Avoid circular dependency
        from core.schemas.graph import RoleRelationship

        async_graph = self._db.graph("systemroles")

        aql = """
        WITH users, groups

        FOR v, e, p IN 1..1 OUTBOUND @extended_id
        acls
          FILTER v._id == @target_extended_id
        RETURN e"""
        args = {
            "extended_id": self.extended_id,
            "target_extended_id": target.extended_id,
        }
        neighbors = self._db.aql.execute(aql, bind_vars=args)
        if not neighbors.empty():
            neighbor = neighbors.pop()
            neighbor["__id"] = neighbor.pop("_key")
            relationship = RoleRelationship.load(neighbor)
            relationship.modified = datetime.datetime.now(datetime.timezone.utc)
            relationship.role = role
            edge = json.loads(relationship.model_dump_json())
            edge["_id"] = neighbor["_id"]
            job = async_graph.update_edge(edge)
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            return relationship

        relationship = RoleRelationship(
            role=role,
            source=self.extended_id,
            target=target.extended_id,
            created=datetime.datetime.now(datetime.timezone.utc),
            modified=datetime.datetime.now(datetime.timezone.utc),
        )
        col = async_graph.edge_collection("acls")
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
        return RoleRelationship.load(result)

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
        user: "user.User | None" = None,
        include_tags: bool = True,
    ) -> tuple[
        dict[
            str,
            "observable.ObservableTypes | entity.EntityTypes | indicator.IndicatorTypes | tag.Tag",
        ],
        List[List["RelationshipTypes"]],
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
            offset: The number of results to skip.
            count: The number of results to return.
            sorting: A list of tuples containing the field to sort on and a boolean
                    indicating if it should be sorted in ascending order.
            user: The user requesting the data; used to take ACLs into account.
            include_tags: Whether to include tags in the result.

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
            sorts.append(f"p.edges[0].{field} {'ASC' if asc else 'DESC'}")
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
                if f.pathcompare.lower() not in {"any", "all", "none"}:
                    f.pathcompare = ""

                if f.operator.lower() not in {"=~", "==", "in"}:
                    f.operator = "=="

                # =~ not compatible with path operators
                if f.operator == "=~":
                    f.pathcompare = ""

                if f.operator in {"=~", "=="}:
                    filters.append(
                        f"(p.edges[*].@filter_key{i} {f.pathcompare} {f.operator} @filter_value{i} OR p.vertices[*].@filter_key{i} {f.pathcompare} {f.operator} @filter_value{i})"
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

        acl_query = ""
        if user and RBAC_ENABLED and not user.admin:
            acl_query = "LET acl = FIRST(FOR aclv in 1..2 inbound v acls FILTER aclv.username == @username RETURN true) or false\n\nfilter acl"
            args["username"] = user.username

        aql = f"""
        WITH observables, entities, dfiq, indicators

        FOR v, e, p IN @min_hops..@max_hops {direction} @extended_id @@graph
          OPTIONS {{ uniqueVertices: "path" }}
          {query_filter}
          {acl_query}
          LET vertices = p['vertices']
          {limit}
          {sorting_aql}
          RETURN {{ vertices: vertices, g: p }}
        """
        neighbors = self._db.aql.execute(
            aql, bind_vars=args, count=True, full_count=True
        )
        total = neighbors.statistics().get("fullCount", count)
        paths = []  # type: list[list[Relationship]]
        vertices = {}  # type: dict[str, ArangoYetiConnector]
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
            if "acls" in edge["_id"]:
                relationships.append(graph.RoleRelationship.load(edge))
            else:
                relationships.append(graph.Relationship.load(edge))
        return relationships

    def _build_vertices(self, vertices, arango_vertices):
        # Import happens here to avoid circular dependency
        from core.schemas import dfiq, entity, indicator, observable, rbac, tag, user

        type_mapping = {
            "tag": tag.Tag,
            "user": user.User,
            "rbacgroup": rbac.Group,
        }
        type_mapping.update(observable.TYPE_MAPPING)
        type_mapping.update(entity.TYPE_MAPPING)
        type_mapping.update(indicator.TYPE_MAPPING)
        type_mapping.update(dfiq.TYPE_MAPPING)

        for vertex in arango_vertices:
            if vertex is None:
                logging.warning(f"Found None vertex from {self.extended_id}")
                continue
            if vertex["_key"] in vertices:
                continue
            vertex_type = vertex.get("type") or vertex.get("root_type") or "tag"
            neighbor_schema = type_mapping[vertex_type]
            vertex["__id"] = vertex.pop("_key")
            if vertex["_id"] not in vertices:
                vertices[vertex["_id"]] = neighbor_schema.load(vertex)

    @classmethod
    def count(cls: Type[TYetiObject]):
        """Counts the number of objects in the collection.

        Returns:
          The number of objects in the collection.
        """
        async_col = cls._db.collection(cls._collection_name)
        job = async_col.count()
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        return job.result()

    @classmethod
    def filter(
        cls: Type[TYetiObject],
        query_args: dict[str, Any],
        offset: int = 0,
        count: int = 0,
        sorting: List[tuple[str, bool]] = [],
        aliases: List[tuple[str, str]] = [],
        graph_queries: List[tuple[str, str, str, str]] = [],
        links_count: bool = False,
        wildcard: bool = True,
        user: "user.User" = None,
    ) -> tuple[List[TYetiObject], int]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            query_args: A key:value dictionary containing keys to filter objects
                on.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.
            sorting: A list of (order, ascending) fields to sort by.
            aliases: A list of (alias, type) tuples to use for filtering.
            graph_queries: A list of (name, graph, direction, field) tuples to
                query the graph with.
            wildcard: whether all values should be interpreted as wildcard searches.
            user: A user to perform the query for.

        Returns:
            A List of Yeti objects, and the total object count.
        """
        cls._get_collection()
        colname = cls._collection_name
        if colname is None:
            colname = "all_objects_view"
        conditions = []
        filter_conditions = []  # used for clauses that are not supported by arangosearch
        sorts = []

        using_view = False
        generic_query = False

        if colname == "all_objects_view":
            generic_query = True
            using_view = True

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
                sorts.append(f"total_links {'ASC' if asc else 'DESC'}")
            else:
                sorts.append(f"o.{field} {'ASC' if asc else 'DESC'}")

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
            elif key == "tags":
                if using_view:
                    conditions.append(
                        f"(FOR t in @arg{i}_value RETURN LOWER(t)) ALL IN o.tags.name"
                    )
                else:
                    conditions.append(
                        f"(FOR t in @arg{i}_value RETURN LOWER(t)) ALL IN o.tags[*].name"
                    )
            elif key in ("created", "modified", "tags.expires"):
                # Value is a string, we're checking the first character.
                operator = value[0]
                if operator not in ["<", ">"]:
                    operator = "="
                else:
                    aql_args[f"arg{i}_value"] = value[1:]
                if key == "tags.expires":
                    filter_conditions.append(
                        f"o.tags[* RETURN DATE_TIMESTAMP(CURRENT.expires)] ANY {operator} DATE_TIMESTAMP(@arg{i}_value)"
                    )
                else:
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
                    if alias == "tags":
                        if using_view:
                            key_conditions.append(
                                f"ANALYZER(LIKE(o.tags.name, LOWER(@arg{i}_value)), 'norm')"
                            )
                        else:
                            key_conditions.append(
                                f"LOWER(@arg{i}_value) IN o.tags[*].name"
                            )
                    if alias_type in {"text", "option", "list"} and using_view:
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
            field_aggregation = "||".join([f"v.{field}" for field in field.split("|")])
            graph_query_string += f"\nLET {name} = (FOR v, e in 1..1 {direction} o {graph} RETURN {{ [{field_aggregation}]: e }})"

        acl_query = ""
        if user and RBAC_ENABLED and not user.admin:
            acl_query = "LET acl = FIRST(FOR v, e, p in 1..2 inbound o acls FILTER v.username == @username RETURN true) or false"
            aql_args["username"] = user.username

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

        acl_filter = ""
        if acl_query:
            acl_filter = "FILTER acl"

        aql_string = f"""
            FOR o IN @@collection
                {aql_search}
                {links_count_query}
                {graph_query_string}
                {acl_query}
                {filter_string}
                {acl_filter}
                {aql_sort}
                {limit}
            """
        merged_list = ""
        with_statements = []
        if graph_queries:
            merged_list = ", ".join(
                [f"{name}: MERGE({name})" for name, _, _, _ in graph_queries]
            )
            with_statements.extend([name for name, _, _, _ in graph_queries])
        if acl_query:
            with_statements.append("acls")
        if links_count:
            merged_list += (
                ", aggregated_links, total_links"
                if merged_list
                else "aggregated_links, total_links"
            )

        prologue = ""
        if with_statements:
            prologue = f"WITH {', '.join(with_statements)}"
        if merged_list:
            aql_string = (
                f"{prologue}\n\n{aql_string}\nRETURN MERGE(o, {{ {merged_list} }})\n"
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
            if not generic_query:
                results.append(cls.load(doc))
            else:
                # Generic objects are not loaded, they are returned as dicts.
                doc["id"] = doc.pop("__id")
                del doc["_id"]
                del doc["_rev"]
                results.append(doc)
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

    def _delete_vertex_refs_in_graphs(self, vertex_id):
        for graph_name in {"tags", "systemroles", "threat_graph"}:
            graph = self._db.graph(graph_name)
            job = graph.edge_definitions()
            while job.status() != "done":
                time.sleep(ASYNC_JOB_WAIT_TIME)
            definitions = job.result()

            for edge_collection in [d["edge_collection"] for d in definitions]:
                job = graph.edge_collection(edge_collection).delete_match(
                    {"_from": vertex_id}
                )
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)
                job = graph.edge_collection(edge_collection).delete_match(
                    {"_to": vertex_id}
                )
                while job.status() != "done":
                    time.sleep(ASYNC_JOB_WAIT_TIME)

    def delete(self, all_versions=True):
        """Deletes an object from the database."""
        # TODO(tomchop): Revisit inheritance model of ArangoDBConnector.
        if hasattr(self, "clear_tags"):
            self.clear_tags()
        col = self._db.collection(self._collection_name)
        self._delete_vertex_refs_in_graphs(self.extended_id)
        job = col.delete(self.id)
        while job.status() != "done":
            time.sleep(ASYNC_JOB_WAIT_TIME)
        if self._collection_name in ("auditlog", "timeline"):
            return
        try:
            event_type = message.EventType.delete
            if self._collection_name == "links":
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
        if cls._collection_name is not None:
            return cls._db.collection(cls._collection_name)
        else:
            return "all_objects_view"


def tagged_observables_export(cls, args):
    aql = """
        FOR o in observables
        FILTER (o.type IN @acts_on OR @acts_on == [])
        FILTER o.tags != []
        LET freshtags = (
            FOR t IN o.tags
                FILTER t.name NOT IN @ignore
                FILTER (t.fresh OR NOT @fresh)
            RETURN t.name
        )
        FILTER COUNT(freshtags) > 0
        FILTER COUNT(INTERSECTION(freshtags, @include)) > 0 OR @include == []
        FILTER COUNT(INTERSECTION(freshtags, @exclude)) == 0
        RETURN o
        """
    documents = db.aql.execute(aql, bind_vars=args, count=True, full_count=True)
    results = []
    for doc in documents:
        doc["__id"] = doc.pop("_key")
        results.append(cls.load(doc))
    return results
