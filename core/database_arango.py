"""Class implementing a YetiConnector interface for ArangoDB."""
import datetime
import json
import sys
import time
from typing import TypeVar, Iterable, Type, Any, List, TYPE_CHECKING, Tuple
if TYPE_CHECKING:
    from core.schemas.graph import Relationship

import requests
from arango import ArangoClient
from arango.exceptions import (DocumentInsertError, DocumentUpdateError,
                               GraphCreateError)
from dateutil import parser

from core.config.config import yeti_config

from .interfaces import AbstractYetiConnector

LINK_TYPE_TO_GRAPH = {
    'tagged': 'tags',
    'stix': 'stix',
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

    def connect(self,
                host: str = None,
                port: int = None,
                username: str = None,
                password: str = None,
                database: str = None):

        host = host or yeti_config.arangodb.host
        port = port or yeti_config.arangodb.port
        username = username or yeti_config.arangodb.username
        password = password or yeti_config.arangodb.password
        database = database or yeti_config.arangodb.database

        host_string = f'http://{host}:{port}'
        client = ArangoClient(hosts=host_string)

        sys_db = client.db('_system', username=username, password=password)
        for _ in range(0, 4):
            try:
                yeti_db = sys_db.has_database(database)
                break
            except requests.exceptions.ConnectionError as e:
                print('Connection error: {0:s}'.format(str(e)))
                print('Retrying in 5 seconds...')
                time.sleep(5)
        else:
            print("Could not connect, bailing.")
            sys.exit(1)

        if not yeti_db:
            sys_db.create_database(database)

        self.db = client.db(database, username=username, password=password)

        self.create_edge_definition(self.graph('tags'), {
            'edge_collection': 'tagged',
            'from_vertex_collections': ['observables'],
            'to_vertex_collections': ['tags'],
        })
        self.create_edge_definition(self.graph('threat_graph'), {
            'edge_collection': 'links',
            'from_vertex_collections': ['observables', 'entities'],
            'to_vertex_collections': ['observables', 'entities'],
        })

    def clear(self, truncate=True):
        if not self.db:
            return
        for collection_data in self.db.collections():
            if collection_data['system']:
                continue
            if truncate:
                collection = self.db.collection(collection_data['name'])
                collection.truncate()
            else:
                self.db.delete_collection(collection_data['name'])
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

        if not self.db.has_collection(definition['edge_collection']):
            collection = graph.create_edge_definition(**definition)
        else:
            collection = graph.edge_collection(definition['edge_collection'])

        self.collections[definition['edge_collection']] = collection
        return collection

    def __getattr__(self, key):
        if self.db is None and not key.startswith('__'):
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
        return self._collection_name + '/' + self.id


    def _insert(self, document_json):
        try:
            newdoc = self._get_collection().insert(
                document_json, return_new=True)['new']
            newdoc['id'] = newdoc.pop('_key')
            return newdoc
        except DocumentInsertError as err:
            if not err.error_code == 1210: # Unique constraint violation
                raise
            conflict = 'name' if 'name' in document_json else 'value'
            error = 'A {0} object with same `{1}` already exists'.format(
                self.__class__.__name__, conflict)
            raise IntegrityError(str(error))

    def _update(self, document_json):
        document = json.loads(document_json)
        document['_key'] = document.pop('id')
        newdoc = self._get_collection().update(
            document, merge=False, return_new=True)['new']
        newdoc['id'] = newdoc.pop('_key')
        return newdoc

    def save(self: TYetiObject) -> TYetiObject:
        """Inserts or updates a Yeti object into the database.

        Returns:
          The created Yeti object."""
        doc_dict = self.dict(exclude_unset=True)
        if doc_dict.get('id') is not None:
            result = self._update(self.json())
        else:
            result = self._insert(self.json())
        return self.__class__(**result)

    def update_links(self, new_id):
        if not self._arango_id:
            return
        graph = self._db.graph('stix')
        neighbors = graph.traverse(
            self._arango_id, direction='any', max_depth=1)
        for path in neighbors['paths']:
            for edge in path['edges']:
                if edge['attributes']['target_ref'] == self.id:
                    edge['_to'] = new_id
                elif edge['attributes']['source_ref'] == self.id:
                    edge['_from'] = new_id
                graph.update_edge(edge)

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
                'FOR o IN @@collection FILTER o.type IN @type RETURN o',
                bind_vars={'type': [type_filter], '@collection': coll})
        else:
            objects = cls._db.aql.execute(
                'FOR o IN @@collection RETURN o',
                bind_vars={'@collection': coll})

        for object in list(objects):
            object['id'] = object.pop('_key')
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
        document['id'] = document.pop('_key')
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
        document['id'] = document.pop('_key')
        return cls.load(document)

    @classmethod
    def get_or_create(cls, **kwargs):
        """Fetches an object matching dict_ or creates it.

        If an object matching kwargs is found, return the existing object. If
        not, create it and return the newly created object.

        Args:
          **kwargs: Dictionary used to create the object.

        Returns:
          A Yeti object.
        """
        obj = cls(**kwargs)
        try:
            return obj.save()
        except IntegrityError:
            return cls.find(**kwargs)

    def link_to(self, target: TYetiObject, relationship_type: str, description: str) -> "Relationship":
        """Creates a link between two YetiObjects.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
        """
        # Avoid circular dependency
        from core.schemas.graph import Relationship
        graph = self._db.graph('threat_graph')

        # Check if a relationship with the same link_type already exists
        aql = f'''
        FOR v, e, p IN 1..1 OUTBOUND "{self.extended_id}"
        links
          FILTER e.type == "{relationship_type}"
          FILTER v._id == "{target.extended_id}"
        RETURN e'''
        neighbors = list(self._db.aql.execute(aql))
        if neighbors:
            relationship = Relationship.load(neighbors[0])
            relationship.modified = datetime.datetime.now(datetime.timezone.utc)
            relationship.description = description
            edge = json.loads(relationship.json())
            edge['_id'] = neighbors[0]['_id']
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
        result = graph.edge_collection('links').link(
            relationship.source,
            relationship.target,
            data=json.loads(relationship.json()),
            return_new=True)['new']
        result['id'] = result.pop('_key')
        return Relationship.load(result)
        # existing = list(Relationship.filter({'attributes.id': stix_rel['id']}))
        # if existing:
        #     return existing[0]
        # # pylint: disable=protected-access
        # return Relationship(self._arango_id, target._arango_id, stix_rel).save()

    # pylint: disable=too-many-arguments
    def neighbors(
        self,
        link_types: List[str] = [],
        target_types: List[str] = [],
        direction: str = 'any',
        include_original: bool = False,
        hops: int = 1,
        offset: int = 0,
        count: int = 0
    ) -> tuple[dict[str, "ArangoYetiConnector"], List["Relationship"], int]:
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
        query_filter = ''
        if link_types:
            link_types_query = ', '.join([f'"{t}"' for t in link_types])
            query_filter = f'FILTER e.type in [{link_types_query}]'
        if target_types:
            target_types_query = ', '.join([f'"{t}"' for t in target_types])
            query_filter += f'\nFILTER v.type in [{target_types_query}]'

        limit = ''
        if offset:
            limit += f'LIMIT {offset}'
            if count:
                limit += f', {count}'

        aql = f"""
        FOR v, e, p IN 1..{hops} {direction} '{self.extended_id}'
          links
          {query_filter}
          {limit}
          RETURN p
        """

        cursor = self._db.aql.execute(aql, count=True, full_count=True)
        count = cursor.count()
        edges = []  # type: list[Relationship]
        vertices = {}  # type: dict[str, ArangoYetiConnector]
        neighbors = list(cursor)
        for path in neighbors:
            edges.extend(self._build_edges(path['edges']))
            self._build_vertices(vertices, path['vertices'])
        if not include_original:
            vertices.pop(self.extended_id, None)
        edges = self._dedup_edges(edges)

        return vertices, edges, count or 0

    def _dedup_edges(self, edges):
        """Deduplicates edges with same STIX ID, keeping the most recent one.

        Args:
          edges: list of JSON-serialized STIX2 SROs.

        Returns:
          A list of the most recent versions of JSON-serialized STIX2 SROs.
        """
        seen = {}
        for edge in edges:
            if edge.id in seen:
                seen_modified = parser.parse(seen[edge.id].modified)
                current_modified = parser.parse(edge.modified)
                if seen_modified > current_modified:
                    continue
            seen[edge.id] = edge
        return list(seen.values())

    def _build_edges(self, arango_edges) -> List["Relationship"]:
        # Avoid circular dependency
        from core.schemas.graph import Relationship
        relationships = []
        for edge in arango_edges:
            edge['id'] = edge.pop('_key')
            edge['source'] = edge.pop('_from')
            edge['target'] = edge.pop('_to')
            relationships.append(Relationship.load(edge))
        return relationships

    def _build_vertices(self, vertices, arango_vertices):
        # Import happens here to avoid circular dependency
        from core.schemas import observable
        from core.schemas import entity

        type_mapping = {}
        type_mapping.update(observable.TYPE_MAPPING)
        type_mapping.update(entity.TYPE_MAPPING)

        for vertex in arango_vertices:
            if vertex['_key'] in vertices:
                continue
            neighbor_schema = type_mapping[vertex['type']]
            vertex['id'] = vertex.pop('_key')
            # We want the "extended ID" here, e.g. observables/12345
            vertices[vertex['_id']] = neighbor_schema.load(vertex)

    @classmethod
    def filter(cls: Type[TYetiObject],
               args: dict[str, Any],
               offset: int = 0,
               count: int = 0) -> List[TYetiObject]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            args: A key:value dictionary containing a 'value' or 'name' key
              defining the regular expression to match against.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.

        Returns:
            A List of Yeti objects
        """
        cls._get_collection()
        colname = cls._collection_name
        conditions = []
        sorts = []
        for key in args:
            if key.startswith('in__'):
                conditions.append(f'@{key} ALL IN o.{key[4:]}')
                sorts.append(f'o.{key[4:]}')
            if key.endswith('__in'):
                conditions.append(f'o.{key[:-4]} IN @{key}')
                sorts.append(f'o.{key[:-4]}')
            if key in ['value', 'name', 'type', 'attributes.id', 'email']:
                conditions.append('o.{0:s} =~ @{1:s}'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))
            if key in ['labels', 'relevant_tags']:
                conditions.append('@{1:s} ALL IN o.{0:s}'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))

        limit = ''
        if offset:
            limit += f'LIMIT {offset}'
            if count:
                limit += f', {count}'

        aql_string = f"""
            FOR o IN @@collection
                FILTER {' AND '.join(conditions)}
                SORT {', '.join(sorts)}
                {limit}
                RETURN o
            """
        args['@collection'] = colname
        for key in list(args.keys()):
            args[key.replace('.', '_')] = args.pop(key)
        documents = cls._db.aql.execute(aql_string, bind_vars=args)
        results = []
        for doc in documents:
            doc['id'] = doc.pop('_key')
            results.append(cls.load(doc))
        return results

    @classmethod
    def fulltext_filter(cls, keywords):
        """Search in an ArangoDB collection using full-text search.

        Args:
          query: Keywords to use in the full-text query.

        Returns:
          A List of Yeti objects.
        """
        collection = cls._get_collection()
        query = ','.join(keywords)
        yeti_objects = []
        key = cls._text_indexes[0]['fields'][0]
        for document in collection.find_by_text(key, query):
            document['id'] = document.pop('_key')
            yeti_objects.append(cls.load(document, strict=True))
        return yeti_objects

    def delete(self, all_versions=True):
        """Deletes an object from the database."""
        if self._db.graph('threat_graph').has_vertex_collection(self._collection_name):
            col = self._db.graph('threat_graph').vertex_collection(self._collection_name)
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
        collection = cls._db.collection(cls._collection_name)
        # for index in cls._indexes:
        #     collection.add_hash_index(**index)
        # for text_index in cls._text_indexes:
        #     collection.add_fulltext_index(**text_index)
        return collection
