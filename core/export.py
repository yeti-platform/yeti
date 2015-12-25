import os
import codecs
import logging
from datetime import datetime
import traceback

from mongoengine import ListField, StringField, Q

from core.config.celeryctl import celery_app
from core.observables import Observable, Tag
from core.scheduling import ScheduleEntry


@celery_app.task
def execute_export(export_id):

    export = Export.objects.get(id=export_id)
    try:
        if export.enabled:
            logging.info("Running export {}".format(export.name))
            export.update_status("Exporting...")
            export.query()
            export.update_status("OK")
        else:
            logging.error("Export {} has been disabled".format(export.name))
    except Exception as e:
        msg = "ERROR executing export: {}".format(e)
        logging.error(msg)
        logging.error(traceback.format_exc())
        export.update_status(msg)

    export.last_run = datetime.now()
    export.save()


class Export(ScheduleEntry):
    include_tags = ListField(StringField())
    exclude_tags = ListField(StringField())
    output_dir = StringField()

    def __init__(self, *args, **kwargs):
        super(Export, self).__init__(*args, **kwargs)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.export_file_handle = codecs.open(self.output_file, 'w+', "utf-8")
        self.include_tags_id = list(Tag.objects(name__in=self.include_tags))
        self.exclude_tags_id = list(Tag.objects(name__in=self.exclude_tags))

    @property
    def output_file(self):
        return os.path.abspath(os.path.join(self.output_dir, self.name))

    def query(self):
        q = Q(tags__name__in=self.include_tags_id) & Q(tags__name__nin=self.exclude_tags_id)
        for o in Observable.objects(q):
            self.format(o)

    def format(self, o):
        self.write("{}\n".format(o.value))

    def write(self, output):
        self.export_file_handle.write(output)

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "enabled", "description", "status", "last_run", "include_tags", "exclude_tags"]}
        i['frequency'] = str(self.frequency)
        i['output_file'] = os.path.abspath(self.output_file)
        i['id'] = str(self.id)
        return i
