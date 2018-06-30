from __future__ import unicode_literals

import logging
import traceback
from bson.dbref import DBRef
from datetime import datetime
from mongoengine import *
from flask_login import current_user
from flask_mongoengine.wtf import model_form
from wtforms.fields import StringField as WTFStringField
from wtforms.fields import HiddenField as WTFHiddenField

from core.database import YetiDocument, AttachedFile
from core.scheduling import OneShotEntry
from core.config.celeryctl import celery_app


class InvestigationLink(EmbeddedDocument):
    id = StringField(required=True)
    fromnode = StringField(required=True)
    tonode = StringField(required=True)
    label = StringField()

    @staticmethod
    def build(data):
        link = InvestigationLink(
            id=data['id'], fromnode=data['from'], tonode=data['to'])
        if 'label' in data:
            link.label = data['label']

        return link


class InvestigationEvent(EmbeddedDocument):
    kind = StringField(required=True)
    links = ListField(EmbeddedDocumentField(InvestigationLink))
    nodes = ListField(ReferenceField('Node'))
    datetime = DateTimeField(default=datetime.utcnow)

def default_user():
    try:
        return current_user.username
    except:
        return None


class Investigation(YetiDocument):
    name = StringField(verbose_name="Name")
    description = StringField(verbose_name="Description")
    links = ListField(EmbeddedDocumentField(InvestigationLink))
    nodes = ListField(ReferenceField('Node', dbref=True))
    events = ListField(EmbeddedDocumentField(InvestigationEvent))
    created_by = StringField(verbose_name="Created By")
    created = DateTimeField(default=datetime.utcnow)
    updated = DateTimeField(default=datetime.utcnow)
    import_document = ReferenceField('AttachedFile')
    import_md = StringField()
    import_url = StringField()
    import_text = StringField()

    exclude_fields = [
        'links', 'nodes', 'events', 'created', 'updated', 'created_by',
        'import_document', 'import_md', 'import_url', 'import_text']

    # Ignore extra fields
    meta = {'strict': False}

    @classmethod
    def get_form(klass):
        """Gets the appropriate form for a given investigation"""
        form = model_form(klass, exclude=klass.exclude_fields)

        # An empty name is the same as no name
        form.name = WTFStringField(
            'Name', filters=[lambda name: name or None])

        form.created_by = WTFHiddenField(
            'created_by', default=default_user)

        return form

    SEARCH_ALIASES = {}

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

    def save(self, *args, **kwargs):
        self.updated = datetime.utcnow()

        return super(Investigation, self).save(*args, **kwargs)


class ImportResults(Document):
    import_method = ReferenceField('ImportMethod', required=True)
    status = StringField(required=True)
    investigation = ReferenceField('Investigation')
    error = StringField()


class ImportMethod(OneShotEntry):
    acts_on = StringField()

    def run(self, target):
        results = ImportResults(import_method=self, status='pending')
        results.investigation = Investigation(created_by=default_user())

        if isinstance(target, AttachedFile):
            results.investigation.import_document = target
            target = target.filepath
        else:
            results.investigation.import_url = target

        results.investigation.save()
        results.save()
        celery_app.send_task(
            "core.investigation.import_task", [str(results.id), target])

        return results


@celery_app.task
def import_task(results_id, target):
    results = ImportResults.objects.get(id=results_id)
    import_method = results.import_method
    logging.warning(
        "Running one-shot import {} on {}".format(
            import_method.__class__.__name__, target))
    results.update(status="running")

    try:
        import_method.do_import(results, target)
        results.update(status="finished")
    except Exception, e:
        results.update(status="error", error=str(e))
        traceback.print_exc()
