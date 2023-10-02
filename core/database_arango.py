"""Class implementing a YetiConnector interface for ArangoDB."""
import datetime
import json
import sys
import time
from typing import TYPE_CHECKING, Any, Iterable, List, Tuple, Type, TypeVar

if TYPE_CHECKING:
    from core.schemas.graph import Relationship
    from core.schemas.graph import TagRelationship
    from core.schemas.tag import Tag

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
            'from_vertex_collections': ['observables', 'entities', 'indicators'],
            'to_vertex_collections': ['observables', 'entities', 'indicators'],
        })
        self.db.collection('observables').add_persistent_index(fields=['value'],unique=True)
        self.db.collection('entities').add_persistent_index(fields=['name'],unique=True)
        self.db.collection('tags').add_persistent_index(fields=['name'],unique=True)
        self.db.collection('indicators').add_persistent_index(fields=['name'],unique=True)

    def clear(self, truncate=True):
        if not self.db:
            self.connect()
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


    def _insert(self, document_json: str):
        document: dict = json.loads(document_json)
        try:
            newdoc = self._get_collection().insert(
                document, return_new=True)['new']
        except DocumentInsertError as err:
            if not err.error_code == 1210: # Unique constraint violation
                raise
            return None

        newdoc['id'] = newdoc.pop('_key')
        return newdoc


    def _update(self, document_json):
        document = json.loads(document_json)
        doc_id = document.pop('id')
        if doc_id:
            document['_key'] = doc_id
            newdoc = self._get_collection().update(
                document, merge=False, return_new=True)['new']
        else:
            if 'value' in document:
                filters = {'value': document['value']}
            else:
                filters = {'name': document['name']}
            self._get_collection().update_match(
                filters, document, merge=False)
            newdoc = list(self._get_collection().find(filters, limit=1))[0]

        newdoc['id'] = newdoc.pop('_key')
        return newdoc

    def save(self: TYetiObject) -> TYetiObject:
        """Inserts or updates a Yeti object into the database.

        We need to pass the JSON representation of the object to the database
        because it may contain fields that are not JSON serializable by arango.

        Returns:
          The created Yeti object."""
        doc_dict = self.dict(exclude_unset=True)
        if doc_dict.get('id') is not None:
            result = self._update(self.json())
        else:
            result = self._insert(self.json())
            if not result:
                result = self._update(self.json(exclude={'created'}))
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

    #TODO: Consider extracting this to its own class, given it's only meant
    # to be called by Observables.
    def observable_tag(self, tag_name: str) -> "TagRelationship":
        """Links an Observable to a Tag object.

        Args:
          tag_name: The name of the tag to link to.
        """
        # Import at runtime to avoid circular dependency.
        from core.schemas.graph import TagRelationship
        from core.schemas.tag import Tag
        graph = self._db.graph('tags')

        tags = self.observable_get_tags()

        for tag_relationship, tag in tags:
            if tag.name != tag_name:
                continue
            tag_relationship.last_seen = datetime.datetime.now(datetime.timezone.utc)
            tag_relationship.fresh = True
            edge = json.loads(tag_relationship.json())
            edge['_id'] = tag_relationship.id
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
            fresh=True,
        )

        result = graph.edge_collection('tagged').link(
            self.extended_id,
            tag_obj.extended_id,
            data=json.loads(tag_relationship.json()),
            return_new=True)['new']
        result['id'] = result.pop('_key')
        return TagRelationship.load(result)

    def observable_expire_tag(self, tag_name: str) -> "TagRelationship":
        """Expires a tag on an Observable.

        Args:
          tag_name: The name of the tag to expire.
        """
        # Avoid circular dependency
        from core.schemas.graph import TagRelationship
        from core.schemas.tag import Tag
        graph = self._db.graph('tags')

        tags = self.observable_get_tags()

        for tag_relationship, tag in tags:
            if tag.name != tag_name:
                continue
            tag_relationship.fresh = False
            edge = json.loads(tag_relationship.json())
            edge['_id'] = tag_relationship.id
            graph.update_edge(edge)
            return tag_relationship

        raise ValueError(f"Tag '{tag_name}' not found on observable '{self.extended_id}'")

    def observable_clear_tags(self):
        """Clears all tags on an Observable."""
        # Avoid circular dependency
        graph = self._db.graph('tags')

        tags = self.observable_get_tags()
        results = graph.edge_collection('tagged').edges(self.extended_id)
        for edge in results['edges']:
            graph.edge_collection('tagged').delete(edge['_id'])

    def link_to(self, target: TYetiObject, relationship_type: str, description: str) -> "Relationship":
        """Creates a link between two YetiObjects.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
          description: A description of the link.
        """
        # Avoid circular dependency
        from core.schemas.graph import Relationship
        graph = self._db.graph('threat_graph')

        # Check if a relationship with the same link_type already exists
        aql = '''
        FOR v, e, p IN 1..1 OUTBOUND @extended_id
        links
          FILTER e.type == @relationship_type
          FILTER v._id == @target_extended_id
        RETURN e'''
        args = {
            'extended_id': self.extended_id,
            'target_extended_id': target.extended_id,
            'relationship_type': relationship_type,
        }
        neighbors = list(self._db.aql.execute(aql, bind_vars=args))
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

    #TODO: Consider extracting this to its own class, given it's only meant
    # to be called by Observables.
    def observable_get_tags(self) -> List[Tuple["TagRelationship", "Tag"]]:
        """Returns the tags linked to this object.

        Returns:
          A list of tuples (TagRelationship, Tag) representing each tag linked
          to this object.
        """
        from core.schemas.graph import TagRelationship
        from core.schemas.tag import Tag
        traversed = self._db.graph('tags').traverse(
            self.extended_id, direction='any', max_depth=1)
        relationships = []
        for path in traversed['paths']:
            if path['edges']:
                tag_data = Tag.load(path['vertices'][1])
                edge_data = path['edges'][0]
                edge_data['id'] = edge_data.pop('_id')
                tag_relationship = TagRelationship.load(edge_data)
                relationships.append((tag_relationship, tag_data))
                self.tags[tag_data.name] = tag_relationship
        return relationships

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
        args = {
            'extended_id': self.extended_id,
        }
        if link_types:
            args['link_types_regex'] = '|'.join(link_types)
            query_filter = 'FILTER e.type =~ @link_types_regex'
        if target_types:
            args['target_types_regex'] = '|'.join(target_types)
            query_filter += '\nFILTER v.type =~ @target_types_regex'

        limit = ''
        if offset:
            limit += f'LIMIT {offset}'
            if count:
                limit += f', {count}'

        aql = f"""
        FOR v, e, p IN 1..{hops} {direction} @extended_id links

          {query_filter}
          LET v_with_tags = (
            FOR observable in p['vertices']
              let innertags = (FOR tag, edge in 1..1 OUTBOUND observable tagged RETURN {{ [tag.name]: edge }})
              RETURN MERGE(observable, {{tags: MERGE(innertags)}})
          )
          {limit}
          RETURN {{ vertices: v_with_tags, edges: p['edges'] }}
        """

        cursor = self._db.aql.execute(aql, bind_vars=args, count=True, full_count=True)
        total = cursor.count()
        edges = []  # type: list[Relationship]
        vertices = {}  # type: dict[str, ArangoYetiConnector]
        neighbors = list(cursor)
        for path in neighbors:
            edges.extend(self._build_edges(path['edges']))
            self._build_vertices(vertices, path['vertices'])
        if not include_original:
            vertices.pop(self.extended_id, None)
        edges = self._dedup_edges(edges)

        return vertices, edges, total or 0

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
        from core.schemas import entity, indicator, observable

        type_mapping = {}
        type_mapping.update(observable.TYPE_MAPPING)
        type_mapping.update(entity.TYPE_MAPPING)
        type_mapping.update(indicator.TYPE_MAPPING)

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
               count: int = 0,
               sorting: List[tuple[str, bool]] = [],
               graph_queries: List[tuple[str, str, str, str]] = []) -> tuple[List[TYetiObject], int]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            args: A key:value dictionary containing a 'value' or 'name' key
              defining the regular expression to match against.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.
            sorting: A list of (order, ascending) fields to sort by.

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

        for key, value in args.items():
            if isinstance(value, str):
                args[key] = value.strip()
            elif isinstance(value, list):
                args[key] = [v.strip() for v in value]

            if key.startswith('in__'):
                conditions.append(f'@{key} ALL IN o.{key[4:]}')
                sorts.append(f'o.{key[4:]}')
            elif key.endswith('__in'):
                conditions.append(f'o.{key[:-4]} IN @{key}')
                sorts.append(f'o.{key[:-4]}')
            elif key in ['value', 'name', 'type', 'attributes.id', 'username']:
                conditions.append('REGEX_TEST(o.{0:s}, @{1:s}, true)'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))
            elif key in ['labels', 'relevant_tags']:
                conditions.append('@{1:s} ALL IN o.{0:s}'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))
            else:
                conditions.append('o.{0:s} == @{0:s}'.format(key))
                sorts.append('o.{0:s}'.format(key))

        limit = ''
        if offset:
            limit += f'LIMIT {offset}'
            if count:
                limit += f', {count}'

        #TODO: Interpolate this query
        graph_query_string = ''
        for name, graph, direction, field in graph_queries:
            graph_query_string += f'\nLET {name} = (FOR v, e in 1..1 {direction} o {graph} RETURN {{ [v.{field}]: e }})'

        aql_string = f"""
            FOR o IN @@collection
                FILTER {' AND '.join(conditions)}
                {graph_query_string}
                SORT {', '.join(sorts)}
                {limit}
            """
        if graph_queries:
            aql_string += f'\nRETURN MERGE(o, {{ {", ".join([f"{name}: MERGE({name})" for name, _, _, _ in graph_queries])} }})'
        else:
            aql_string += '\nRETURN o'
        args['@collection'] = colname
        for key in list(args.keys()):
            args[key.replace('.', '_')] = args.pop(key)
        documents = cls._db.aql.execute(
            aql_string, bind_vars=args, count=True, full_count=True)
        results = []
        total = documents.count()
        for doc in documents:
            doc['id'] = doc.pop('_key')
            results.append(cls.load(doc))
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
        return cls._db.collection(cls._collection_name)

class ObservableYetiConnector(ArangoYetiConnector):

    @classmethod
    def filter(cls: Type[TYetiObject],
               args: dict[str, Any],
               tags: List[str] = [],
               offset: int = 0,
               count: int = 0,
               sorting: List[tuple[str, bool]] = []) -> tuple[List[TYetiObject], int]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            args: A key:value dictionary containing a 'value' or 'name' key
                defining the regular expression to match against.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.
            sorting: A list of (order, ascending) fields to sort by.

        Returns:
            A List of Yeti objects, and the total object count.
        """
        cls._get_collection()
        conditions = []
        sorts = []
        tags = args.pop('tags', [])

        # We want user-defined sorts to take precedence.
        for field, asc in sorting:
            sorts.append(f'o.{field} {"ASC" if asc else "DESC"}')

        for key, value in args.items():
            if isinstance(value, str):
                args[key] = value.strip()
            elif isinstance(value, list):
                args[key] = [v.strip() for v in value]

            if key.startswith('in__'):
                conditions.append(f'@{key} ALL IN o.{key[4:]}')
                sorts.append(f'o.{key[4:]}')
            elif key.endswith('__in'):
                conditions.append(f'o.{key[:-4]} IN @{key}')
                sorts.append(f'o.{key[:-4]}')
            elif key == 'value':
                conditions.append('REGEX_TEST(o.value, @value, true)')
                sorts.append('o.{0:s}'.format(key))
            elif key in ['labels', 'relevant_tags']:
                conditions.append('@{1:s} ALL IN o.{0:s}'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))
            else:
                conditions.append('o.{0:s} == @{0:s}'.format(key))
                sorts.append('o.{0:s}'.format(key))

        tag_filter = ''
        if tags:
            tag_filter = "FILTER COUNT(INTERSECTION(ATTRIBUTES(tags), @tag_names)) > 0"
            args['tag_names'] = tags

        limit = ''
        if count != 0:
            limit = f'LIMIT @offset, @count'
            args['offset'] = offset
            args['count'] = count

        aql_string = f"""
            FOR o IN observables
                FILTER {' AND '.join(conditions)}
                LET tags = MERGE(
                    FOR v, e in 1..1 OUTBOUND o tagged RETURN {{ [v.name]: e }}
                )
                {tag_filter}
                SORT {', '.join(sorts)}
                {limit}
            """

        aql_string += '\nRETURN MERGE(o, { tags: tags })'

        documents = cls._db.aql.execute(
            aql_string, bind_vars=args, count=True, full_count=True)
        results = []
        total = documents.statistics().get('fullCount', count)
        for doc in documents:
            doc['id'] = doc.pop('_key')
            results.append(cls.load(doc))
        return results, total or 0


def tagged_observables_export(cls, args):
    aql = """
        FOR o in observables
        FILTER (o.type IN @acts_on OR @acts_on == [])
        LET tagnames = (
                FOR v, e in 1..1 OUTBOUND o tagged
                    FILTER v.name NOT IN @ignore
                    FILTER (e.fresh OR NOT @fresh)
                RETURN v.name
        )
        FILTER tagnames != []
        FILTER (@include ANY IN tagnames OR @include == [])
        FILTER @exclude NONE IN tagnames
        RETURN o
        """
    documents = db.aql.execute(
        aql, bind_vars=args, count=True, full_count=True)
    results = []
    for doc in documents:
        doc['id'] = doc.pop('_key')
        results.append(cls.load(doc))
    return results
