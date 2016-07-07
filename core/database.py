from __future__ import unicode_literals

import re
import os
from datetime import datetime

from wtforms import widgets, Field, StringField
from mongoengine import *
from flask_mongoengine.wtf import model_form

from core.constants import STORAGE_ROOT
from core.helpers import iterify, stream_sha256


class StringListField(Field):
    widget = widgets.TextInput()

    def _value(self):
        if self.data:
            return u','.join([unicode(d) for d in self.data])
        else:
            return u''

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = [x.strip() for x in valuelist[0].split(',')]
        else:
            self.data = []


class TagListField(StringListField):
    endpoint = "api.Tag:index"


class EntityListField(StringListField):
    endpoint = "api.Entity:index"


class YetiDocument(Document):
    meta = {
        "abstract": True,
    }

    def clean_update(self, **kwargs):
        for key, value in kwargs.iteritems():
            setattr(self, key, value)

        self.validate()

        update_dict = {}
        for key, value in kwargs.iteritems():
            update_dict[key] = getattr(self, key, value)

        self.update(**update_dict)
        self.reload()
        return self

    def _set_update(self, method, field, value):
        result = self.__class__._get_collection().update_one({'_id': self.pk}, {method: {field: value}})

        return result.modified_count == 1

    def add_to_set(self, field, value):
        return self._set_update('$addToSet', field, value)

    def remove_from_set(self, field, value):
        return self._set_update('$pull', field, value)


class LinkHistory(EmbeddedDocument):

    description = StringField()
    first_seen = DateTimeField(default=datetime.utcnow)
    last_seen = DateTimeField(default=datetime.utcnow)
    sources = ListField(StringField())
    active = BooleanField()


class Link(Document):

    src = ReferenceField("Node", required=True, dbref=True)
    dst = ReferenceField("Node", required=True, dbref=True, unique_with='src')
    history = ListField(EmbeddedDocumentField(LinkHistory))

    meta = {
        "indexes": [
            "src",
            "dst"
        ]
    }

    def __unicode__(self):
        return u"{} -> {} ({})".format(self.src, self.dst, self.description)

    @property
    def active(self):
        last_history = self._get_last_history()

        if last_history:
            return last_history.active

    @property
    def description(self):
        last_history = self._get_last_history()

        if last_history:
            return last_history.description

    @description.setter
    def description(self, value):
        last_history = self._get_last_history()

        if last_history:
            last_history.description = value

    @property
    def last_seen(self):
        last_history = self._get_last_history()

        if last_history:
            return last_history.last_seen

    @property
    def first_seen(self):
        last_history = self._get_last_history()

        if last_history:
            return last_history.first_seen

    @staticmethod
    def connect(src, dst):
        try:
            l = Link(src=src, dst=dst).save()
        except NotUniqueError:
            l = Link.objects.get(src=src, dst=dst)
        return l

    def info(self):
        return {"description": self.description, "id": str(self.id), "src": unicode(self.src), "dst": unicode(self.dst)}

    def to_dict(self):
        result = self.to_mongo()
        result['description'] = self.description
        result['first_seen'] = self.first_seen
        result['last_seen'] = self.last_seen
        result['active'] = self.active

        return result

    def add_history(self, source, description=None, first_seen=None, last_seen=None, active=False):
        last_seen = last_seen or datetime.utcnow()
        first_seen = first_seen or datetime.utcnow()

        # Do we have to extend current active record ?
        if active:
            active_history = self.get_active(description)
            if active_history and last_seen > active_history.last_seen:
                active_history.last_seen = last_seen
                self.save(validate=False)
                return self
        # Do we have to extend an inactive record ?
        else:
            index, overlapping_history = self._get_overlapping(description, first_seen, last_seen)
            if overlapping_history:
                if source not in overlapping_history.sources:
                    overlapping_history.sources.append(source)

                overlapping_history.first_seen = min(overlapping_history.first_seen, first_seen)
                overlapping_history.last_seen = max(overlapping_history.last_seen, last_seen)
                self.save(validate=False)
                return self

        # Otherwise, just create a new record
        return self.modify(
            push__history=LinkHistory(
                description=description,
                first_seen=first_seen or datetime.utcnow(),
                last_seen=last_seen or datetime.utcnow(),
                active=active,
                sources=[source]))

    def get_active(self, description):
        for item in self.history:
            if item.active and description == item.description:
                return item

        return None

    def _get_overlapping(self, description, first_seen, last_seen):
        for index, item in enumerate(self.history):
            if (description == item.description and
                ((item.first_seen <= first_seen <= item.last_seen) or
                 (item.first_seen <= last_seen <= item.last_seen) or
                 (first_seen <= item.first_seen <= item.last_seen <= last_seen))):
                return index, item

        return None, None

    def _get_last_history(self):
        last_history = None
        last_seen = datetime(1970, 1, 1)

        for history in self.history:
            if history.last_seen > last_seen:
                last_seen = history.last_seen
                last_history = history

        return last_history


class AttachedFile(YetiDocument):
    filename = StringField(required=True)
    sha256 = StringField(required=True)
    content_type = StringField(required=True)
    references = IntField(default=0)

    @staticmethod
    def from_upload(file):
        sha256 = stream_sha256(file.stream)

        try:
            return AttachedFile.objects.get(sha256=sha256)
        except DoesNotExist:
            # First, make sure the storage dir exists
            try:
                os.makedirs(STORAGE_ROOT)
            except:
                pass

            fd = open(os.path.join(STORAGE_ROOT, sha256), 'wb')
            fd.write(file.stream.read())
            fd.close()
            print repr(file.filename), bool(file.filename)
            if file.filename:
                f = AttachedFile(filename=file.filename, content_type=file.content_type, sha256=sha256)
                f.save()
                return f
            else:
                return None

    @property
    def filepath(self):
        return os.path.join(STORAGE_ROOT, self.sha256)

    def contents(self):
        return open(self.filepath, 'rb')

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["filename", "sha256", "content_type"]}
        return i

    def attach(self, obj):
        obj.attached_files.append(self)
        obj.save()
        self.update(inc__references=1)

    def detach(self, obj):
        obj.update(pull__attached_files=self)
        self.modify(dec__references=1)
        if self.references == 0:
            os.remove(self.filepath)
            self.delete()


class Node(YetiDocument):

    exclude_fields = ['attached_files']
    attached_files = ListField(ReferenceField(AttachedFile, reverse_delete_rule=PULL))

    meta = {
        "abstract": True,
    }

    @classmethod
    def get_form(klass):
        form = model_form(klass, exclude=klass.exclude_fields)
        return form

    @property
    def type(self):
        return self._cls.split(".")[-1]

    @property
    def full_type(self):
        return self._cls

    @classmethod
    def get_or_create(cls, **kwargs):
        """Attempts to fetch a node in the database, and creates it if nonexistent"""
        obj = cls(**kwargs)
        try:
            return obj.save()
        except NotUniqueError:
            if hasattr(obj, 'name'):
                return cls.objects.get(name=obj.name)
            if hasattr(obj, 'value'):
                return cls.objects.get(value=obj.value)

    def incoming(self):
        return [(l, l.src) for l in Link.objects(__raw__={"dst.$id": self.id})]

    def outgoing(self):
        return [(l, l.dst) for l in Link.objects(__raw__={"src.$id": self.id})]

    def neighbors(self, neighbor_type=""):
        links = list(set(self.incoming() + self.outgoing()))
        info = {}
        for link, node in links:
            if re.search(neighbor_type.lower(), node.full_type.lower()):
                info[node.full_type] = info.get(node.full_type, []) + [(link, node)]
        return info

    def neighbors_advanced(self, klass, filter, regex, ignorecase, page, rng):
        from core.web.helpers import get_queryset

        out = [(l, l.dst) for l in Link.objects(__raw__={"src.$id": self.id, "dst.cls": re.compile(klass._class_name)}).no_dereference()]
        inc = [(l, l.src) for l in Link.objects(__raw__={"dst.$id": self.id, "src.cls": re.compile(klass._class_name)}).no_dereference()]

        all_links = {ref.id: link for link, ref in inc + out}
        filter['id__in'] = all_links.keys()

        objs = list(get_queryset(klass, filter, regex, ignorecase).limit(rng).skip(page * rng))

        final_list = [(all_links[obj.id], obj) for obj in objs]

        return final_list

    def delete(self):
        Link.objects(Q(src=self) | Q(dst=self)).delete()
        super(Node, self).delete()

    def to_dict(self):
        return self._fields

    # This will only create unactive outgoing links
    def link_to(self, nodes, description, source, first_seen=None, last_seen=None):
        links = set()
        nodes = iterify(nodes)

        for node in nodes:
            link = Link.connect(self, node)
            link.add_history(source, description, first_seen, last_seen)
            links.add(link)

        return list(links)

    # This will only create active outgoing links and will deactivate old links
    def active_link_to(self, nodes, description, source, clean_old=True):
        links = set()
        nodes = iterify(nodes)

        for node in nodes:
            link = Link.connect(self, node)
            link.add_history(source, description, active=True)
            links.add(link)

            if clean_old:
                for link, node in self.outgoing():
                    if node not in nodes:
                        active_link = link.get_active(description)
                        if active_link:
                            active_link.active = False
                            link.save(validate=False)

        return list(links)
