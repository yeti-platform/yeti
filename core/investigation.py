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
    datetime = DateTimeField(default=datetime.now)


class Investigation(YetiDocument):
    name = StringField()
    description = StringField()
    links = ListField(EmbeddedDocumentField(InvestigationLink))
    nodes = ListField(ReferenceField('Node', dbref=True))
    events = ListField(EmbeddedDocumentField(InvestigationEvent))

    def info(self):
        result = self.to_mongo()
        result['nodes'] = [node.to_mongo() for node in self.nodes]

        return result

    def add(self, links, nodes):
        event = InvestigationEvent(kind='add')

        for link in links:
            link = InvestigationLink.build(link)
            if self.add_to_set('links', link.to_mongo()):
                event.links.append(link)

        for node in nodes:
            if not isinstance(node, DBRef):
                node = node.to_dbref()

            if self.add_to_set('nodes', node):
                event.nodes.append(node)

        if len(event.nodes) > 0 or len(event.links) > 0:
            self.modify(push__events=event)
