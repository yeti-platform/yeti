from __future__ import unicode_literals

from bson.dbref import DBRef
from datetime import datetime
from mongoengine import *

from core.database import YetiDocument


class InvestigationLink(EmbeddedDocument):
    id = StringField(required=True)
    fromnode = StringField(required=True)
    tonode = StringField(required=True)
    label = StringField()

    @staticmethod
    def build(data):
        link = InvestigationLink(id=data['id'], fromnode=data['from'], tonode=data['to'])
        if 'label' in data:
            link.label = data['label']

        return link


class InvestigationEvent(EmbeddedDocument):
    kind = StringField(required=True)
    links = ListField(EmbeddedDocumentField(InvestigationLink))
    nodes = ListField(ReferenceField('Node'))
    datetime = DateTimeField(default=datetime.utcnow)


class Investigation(YetiDocument):
    name = StringField()
    description = StringField()
    links = ListField(EmbeddedDocumentField(InvestigationLink))
    nodes = ListField(ReferenceField('Node', dbref=True))
    events = ListField(EmbeddedDocumentField(InvestigationEvent))
    created = DateTimeField(default=datetime.utcnow)
    updated = DateTimeField(default=datetime.utcnow)

    def info(self):
        result = self.to_mongo()
        result['nodes'] = [node.to_mongo() for node in self.nodes]

        return result

    def _node_changes(self, kind, method, links, nodes):
        event = InvestigationEvent(kind=kind)

        for link in links:
            link = InvestigationLink.build(link)
            if method('links', link.to_mongo()):
                event.links.append(link)

        for node in nodes:
            if not isinstance(node, DBRef):
                node = node.to_dbref()

            if method('nodes', node):
                event.nodes.append(node)

        if len(event.nodes) > 0 or len(event.links) > 0:
            self.modify(push__events=event, updated=datetime.utcnow())

    def add(self, links, nodes):
        self._node_changes('add', self.add_to_set, links, nodes)

    def remove(self, links, nodes):
        self._node_changes('remove', self.remove_from_set, links, nodes)
