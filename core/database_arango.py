"""Class implementing a YetiConnector interface for ArangoDB."""
import datetime
import json
import logging
import sys
import time
from typing import TYPE_CHECKING, Any, Iterable, List, Optional, Tuple, Type, TypeVar

if TYPE_CHECKING:
    from core.schemas import entity, indicator, observable
    from core.schemas.graph import Relationship, RelationshipTypes, TagRelationship
    from core.schemas.tag import Tag

import requests
from arango import ArangoClient
from arango.exceptions import DocumentInsertError, GraphCreateError

from core.config.config import yeti_config

from .interfaces import AbstractYetiConnector

LINK_TYPE_TO_GRAPH = {
    "tagged": "tags",
    "stix": "stix",
}

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
    ):
        host = host or yeti_config.get("arangodb", "host")
        port = port or yeti_config.get("arangodb", "port")
        username = username or yeti_config.get("arangodb", "username")
        password = password or yeti_config.get("arangodb", "password")
        database = database or yeti_config.get("arangodb", "database")

        host_string = f"http://{host}:{port}"
        client = ArangoClient(hosts=host_string)

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
                "from_vertex_collections": ["observables", "entities", "indicators"],
                "to_vertex_collections": ["observables", "entities", "indicators"],
            },
        )
        self.db.collection("observables").add_persistent_index(
            fields=["value", "type"], unique=True
        )
        self.db.collection("entities").add_persistent_index(
            fields=["name", "type"], unique=True
        )
        self.db.collection("tags").add_persistent_index(fields=["name"], unique=True)
        self.db.collection("indicators").add_persistent_index(
            fields=["name", "type"], unique=True
        )

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
            if self.db.has_collection(name):
                self.collections[name] = self.db.collection(name)
            else:
                self.collections[name] = self.db.create_collection(name)

        return self.collections[name]

    def graph(self, name):
        if self.db is None:
            self.connect()

        try:
            return self.db.create_graph(name)
        except GraphCreateError as err:
            if err.error_code in [1207, 1925]:
                return self.db.graph(name)
            raise

    def create_edge_definition(self, graph, definition):
        if self.db is None:
            self.connect()

        if not self.db.has_collection(definition["edge_collection"]):
            collection = graph.create_edge_definition(**definition)
        else:
            collection = graph.edge_collection(definition["edge_collection"])

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
        document: dict = json.loads(document_json)
        try:
            newdoc = self._get_collection().insert(document, return_new=True)["new"]
        except DocumentInsertError as err:
            if not err.error_code == 1210:  # Unique constraint violation
                raise
            return None

        newdoc["__id"] = newdoc.pop("_key")
        return newdoc

    def _update(self, document_json):
        document = json.loads(document_json)
        doc_id = document.pop("id")
        if doc_id:
            document["_key"] = doc_id
            newdoc = self._get_collection().update(document, return_new=True)["new"]
        else:
            if "value" in document:
                filters = {"value": document["value"]}
            else:
                filters = {"name": document["name"]}
            if "type" in document:
                filters["type"] = document["type"]
            self._get_collection().update_match(filters, document)

            logging.debug(f"filters: {filters}")
            newdoc = list(self._get_collection().find(filters, limit=1))[0]

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
        doc_dict = self.model_dump(exclude_unset=True, exclude=["tags"])
        if doc_dict.get("id") is not None:
            result = self._update(self.model_dump_json(exclude=["tags"]))
        else:
            result = self._insert(self.model_dump_json(exclude=["tags", "id"]))
            if not result:
                result = self._update(self.model_dump_json(exclude=exclude_overwrite))
        yeti_object = self.__class__(**result)
        # TODO: Override this if we decide to implement YetiTagModel
        if hasattr(self, "tags"):
            yeti_object.get_tags()
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
        document = cls._get_collection().get(id)
        if not document:
            return None
        document["__id"] = document.pop("_key")
        return cls.load(document)

    @classmethod
    def find(cls: Type[TYetiObject], **kwargs) -> TYetiObject | None:
        """Fetches a single object by value.

        Args:
          value: The value to search for.

        Returns:
          A Yeti object.
        """
        documents = list(cls._get_collection().find(kwargs, limit=1))
        if not documents:
            return None
        document = documents[0]
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

        expiration = expiration or tag.DEFAULT_EXPIRATION
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

            tag_link = self.link_to_tag(new_tag.name, expiration=expiration)
            self._tags[new_tag.name] = tag_link

            extra_tags |= set(new_tag.produces)

        extra_tags -= set(tags)
        if extra_tags:
            self.tag(list(extra_tags))

        return self

    def link_to_tag(self, tag_name: str, expiration: datetime.timedelta) -> "TagRelationship":
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

        result = graph.edge_collection("tagged").link(
            self.extended_id,
            tag_obj.extended_id,
            data=json.loads(tag_relationship.model_dump_json()),
            return_new=True,
        )["new"]
        result["__id"] = result.pop("_key")
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
        results = graph.edge_collection("tagged").edges(self.extended_id)
        for edge in results["edges"]:
            graph.edge_collection("tagged").delete(edge["_id"])

    def link_to(
        self, target: TYetiObject, relationship_type: str, description: str
    ) -> "Relationship":
        """Creates a link between two YetiObjects.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
          description: A description of the link.
        """
        # Avoid circular dependency
        from core.schemas.graph import Relationship

        graph = self._db.graph("threat_graph")

        # Check if a relationship with the same link_type already exists
        aql = """
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
            edge = json.loads(relationship.model_dump_json())
            edge["_id"] = neighbors[0]["_id"]
            graph.update_edge(edge)
            return relationship

        relationship = Relationship(
            type=relationship_type,
            source=self.extended_id,
            target=target.extended_id,
            description=description,
            created=datetime.datetime.now(datetime.timezone.utc),
            modified=datetime.datetime.now(datetime.timezone.utc),
        )
        result = graph.edge_collection("links").link(
            relationship.source,
            relationship.target,
            data=json.loads(relationship.model_dump_json()),
            return_new=True,
        )["new"]
        result["__id"] = result.pop("_key")
        return Relationship.load(result)

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

        traversed = self._db.graph("tags").traverse(
            self.extended_id, direction="any", max_depth=1
        )
        relationships = []
        for path in traversed["paths"]:
            if path["edges"]:
                tag_data = Tag.load(path["vertices"][1])
                edge_data = path["edges"][0]
                # edge_data["id"] = edge_data.pop("_id")
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
        include_original: bool = False,
        hops: int = 1,
        offset: int = 0,
        count: int = 0,
    ) -> tuple[
        dict[
            str, "observable.Observable | entity.Entity | indicator.Indicator | tag.Tag"
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
          hops: The maximum number of nodes to go through (defaults to 1:
              direct neighbors)
          raw: Whether to return a raw dictionary or a Yeti object.

        Returns:
          A tuple of two lists: the first one contains the neighbors (vertices),
            the second one contains the relationships (edges)
        """
        query_filter = ""
        args = {
            "extended_id": self.extended_id,
            "@graph": graph,
        }
        if link_types:
            args["link_types"] = link_types
            query_filter = (
                "FILTER COUNT(FOR r IN @link_types FILTER e.type == r RETURN r) > 0"
            )
        if target_types:
            args["target_types"] = target_types
            query_filter = (
                "FILTER COUNT(FOR r IN @target_types FILTER v.type == r RETURN r) > 0"
            )

        limit = ""
        if count != 0:
            limit += "LIMIT @offset, @count"
            args["offset"] = offset
            args["count"] = count

        args["hops"] = hops
        if direction not in {"any", "inbound", "outbound"}:
            direction = "any"

        aql = f"""
        FOR v, e, p IN @hops..@hops {direction} @extended_id @@graph

          {query_filter}
          LET v_with_tags = (
            FOR observable in p['vertices']
              let innertags = (FOR tag, edge in 1..1 OUTBOUND observable tagged RETURN {{ [tag.name]: edge }})
              RETURN MERGE(observable, {{tags: MERGE(innertags)}})
          )
          {limit}
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
        from core.schemas import entity, indicator, observable, tag

        type_mapping = {
            "tag": tag.Tag,
        }
        type_mapping.update(observable.TYPE_MAPPING)
        type_mapping.update(entity.TYPE_MAPPING)
        type_mapping.update(indicator.TYPE_MAPPING)

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
        graph_queries: List[tuple[str, str, str, str]] = [],
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

        Returns:
            A List of Yeti objects, and the total object count.
        """
        cls._get_collection()
        colname = cls._collection_name
        conditions = []
        sorts = []

        # We want user-defined sorts to take precedence.
        for field, asc in sorting:
            sorts.append(f'o.{field} {"ASC" if asc else "DESC"}')

        aql_args: dict[str, str | int | list] = {}
        for i, (key, value) in enumerate(list(query_args.items())):
            if isinstance(value, str):
                aql_args[f"arg{i}_value"] = value
            elif isinstance(value, list):
                aql_args[f"arg{i}_value"] = [v.strip() for v in value]

            if key.startswith("in__"):
                conditions.append(f"@arg{i}_value ALL IN o.@arg{i}_key")
                aql_args[f"arg{i}_key"] = key[4:]
                sorts.append(f"o.@arg{i}_key")
            elif key.endswith("__in"):
                conditions.append(f"o.@arg{i}_key IN @arg{i}_value")
                aql_args[f"arg{i}_key"] = key[:-4]
                sorts.append(f"o.@arg{i}_key")
            elif key in ["labels", "relevant_tags"]:
                conditions.append(f"@arg{i}_value ALL IN o.@arg{i}_key")
                aql_args[f"arg{i}_key"] = key
                sorts.append(f"o.@arg{i}_key")
            elif key.startswith("context."):
                context_field = key[8:]
                conditions.append(
                    f"COUNT(FOR c IN o.context[*] FILTER REGEX_TEST(c.@arg{i}_key, @arg{i}_value) RETURN c) > 0"
                )
                aql_args[f"arg{i}_key"] = context_field
                sorts.append(f"o.context[*].@arg{i}_key")
            elif key in ("created", "expires"):
                operator = value[0]
                if operator not in ["<", ">"]:
                    operator = "="
                else:
                    aql_args[f"arg{i}_value"] = value[1:]
                conditions.append(
                    f"DATE_TIMESTAMP(o.{key}) {operator}= DATE_TIMESTAMP(@arg{i}_value)"
                )
                sorts.append(f"o.{key}")
            else:
                conditions.append(f"REGEX_TEST(o.@arg{i}_key, @arg{i}_value, true)")
                aql_args[f"arg{i}_key"] = key
                sorts.append(f"o.@arg{i}_key")

        limit = ""
        if count != 0:
            limit = "LIMIT @offset, @count"
            aql_args["offset"] = offset
            aql_args["count"] = count

        # TODO: Interpolate this query
        graph_query_string = ""
        for name, graph, direction, field in graph_queries:
            graph_query_string += f"\nLET {name} = (FOR v, e in 1..1 {direction} o {graph} RETURN {{ [v.{field}]: e }})"

        if tag_filter:
            conditions.append(
                "COUNT(INTERSECTION(ATTRIBUTES(MERGE(tags)), @tag_names)) > 0"
            )
            aql_args["tag_names"] = tag_filter

        aql_filter = ""
        if conditions:
            aql_filter = f"FILTER {' AND '.join(conditions)}"

        aql_sort = ""
        if sorts:
            aql_sort = f"SORT {', '.join(sorts)}"

        aql_string = f"""
            FOR o IN @@collection
                {graph_query_string}
                {aql_filter}
                {aql_sort}
                {limit}
            """
        if graph_queries:
            aql_string += f'\nRETURN MERGE(o, {{ {", ".join([f"{name}: MERGE({name})" for name, _, _, _ in graph_queries])} }})'
        else:
            aql_string += "\nRETURN o"
        aql_args["@collection"] = colname
        # print(aql_string)
        # print(aql_args)
        documents = cls._db.aql.execute(
            aql_string, bind_vars=aql_args, count=True, full_count=True
        )
        results = []
        total = documents.statistics().get("fullCount", count)
        for doc in documents:
            doc["__id"] = doc.pop("_key")
            results.append(cls.load(doc))
        return results, (total or 0)

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
        if self._db.graph("threat_graph").has_vertex_collection(self._collection_name):
            col = self._db.graph("threat_graph").vertex_collection(
                self._collection_name
            )
        else:
            col = self._db.collection(self._collection_name)
        col.delete(self.id)

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
