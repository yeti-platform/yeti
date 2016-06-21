from __future__ import unicode_literals

import os
import codecs
import logging
from datetime import datetime
import traceback
import hashlib

from mongoengine import ListField, StringField, Q, ReferenceField, PULL
from jinja2 import Environment, FileSystemLoader
from flask import url_for
from mongoengine import DoesNotExist

from core.database import YetiDocument
from core.config.celeryctl import celery_app
from core.observables import Observable, Tag
from core.scheduling import ScheduleEntry


class ExportTemplate(YetiDocument):
    name = StringField(required=True, max_length=255, verbose_name="Name")
    template = StringField(required=True, default="")

    def render(self, elements, output_filename):
        env = Environment(loader=FileSystemLoader('core/web/frontend/templates'))
        template = env.from_string(self.template)
        temp_filename = "{}.temp".format(output_filename)
        m = hashlib.md5()
        with codecs.open(temp_filename, 'w+', encoding='utf-8') as tmp:
            for chunk in template.stream(elements=elements):
                tmp.write(chunk)
                m.update(chunk.encode('utf-8'))

        try:
            os.remove(output_filename)
        except OSError:
            pass
        os.rename(temp_filename, output_filename)

        return m.hexdigest()

    def info(self):
        return {
            "name": self.name,
            "template": self.template,
            "id": self.id
            }


@celery_app.task
def execute_export(export_id):

    try:
        export = Export.objects.get(id=export_id, lock=None)  # check if we have implemented locking mechanisms
    except DoesNotExist:
        try:
            Export.objects.get(id=export_id, lock=False).modify(lock=True)  # get object and change lock
            export = Export.objects.get(id=export_id)
        except DoesNotExist:
            # no unlocked Export was found, notify and return...
            logging.info("Export {} is already running...".format(Export.objects.get(id=export_id).name))
            return

    try:
        if export.enabled:
            logging.info("Running export {}".format(export.name))
            export.update_status("Exporting...")
            export.hash_md5 = export.execute()
            export.update_status("OK")
        else:
            logging.error("Export {} has been disabled".format(export.name))
    except Exception as e:
        msg = "ERROR executing export: {}".format(e)
        logging.error(msg)
        logging.error(traceback.format_exc())
        export.update_status(msg)

    if export.lock:  # release lock if it was set
        export.lock = False

    export.last_run = datetime.utcnow()
    export.save()


class Export(ScheduleEntry):

    SCHEDULED_TASK = 'core.exports.export.execute_export'
    CUSTOM_FILTER = Q()

    include_tags = ListField(ReferenceField(Tag, reverse_delete_rule=PULL))
    exclude_tags = ListField(ReferenceField(Tag, reverse_delete_rule=PULL))
    ignore_tags = ListField(ReferenceField(Tag, reverse_delete_rule=PULL))
    output_dir = StringField(default='exports')
    acts_on = StringField(verbose_name="Acts on", required=True)
    template = ReferenceField(ExportTemplate)
    hash_md5 = StringField(max_length=32)

    def __init__(self, *args, **kwargs):
        super(Export, self).__init__(*args, **kwargs)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    @property
    def output_file(self):
        return os.path.abspath(os.path.join(self.output_dir, self.name))

    @property
    def content_uri(self):
        return url_for("api.Export:content", id=str(self.id))

    def execute(self):
        q_include = Q()
        for t in self.include_tags:
            q_include |= Q(tags__match={'name': t.name, 'fresh': True})
        q_exclude = Q(tags__name__nin=[t.name for t in self.exclude_tags])
        q = Q(tags__not__size=0) & q_include & q_exclude & Q(_cls="Observable.{}".format(self.acts_on))

        return self.template.render(self.filter_ignore_tags(Observable.objects(q).no_cache()), self.output_file)

    def filter_ignore_tags(self, elements):
        ignore = set([t.name for t in self.ignore_tags])
        for e in elements:
            if set([t.name for t in e.tags]) - ignore:
                yield e

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "output_dir", "enabled", "description", "status", "last_run", "ignore_tags", "include_tags", "exclude_tags"]}
        i['frequency'] = str(self.frequency)
        i['id'] = str(self.id)
        i['ignore_tags'] = [tag.name for tag in self.ignore_tags]
        i['include_tags'] = [tag.name for tag in self.include_tags]
        i['exclude_tags'] = [tag.name for tag in self.exclude_tags]
        i['template'] = self.template.name
        i['acts_on'] = self.acts_on
        i['content_uri'] = self.content_uri
        return i
