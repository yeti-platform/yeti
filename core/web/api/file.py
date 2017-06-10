from __future__ import unicode_literals

from StringIO import StringIO
import zipfile

from flask_classy import route
from flask import request, Response, abort
import magic
from mongoengine import DoesNotExist

from core.web.api.crud import CrudApi
from core import observables
from core.web.helpers import requires_permissions
from core.web.api.api import render_json
from core.helpers import stream_sha256
from core.database import AttachedFile


def save_file(uploaded_file, filename=None):
    value = "FILE:{}".format(stream_sha256(uploaded_file))
    f = observables.File.get_or_create(value=value)
    f.mime_type = magic.from_buffer(uploaded_file.read(100), mime=True)

    if not filename:
        filename = uploaded_file.filename
    if filename not in f.filenames:
        f.filenames.append(filename)

    if not f.body:
        uploaded_file.seek(0)
        f.body = AttachedFile.from_upload(uploaded_file, force_mime=f.mime_type)

    return f.save()


def save_uploaded_files():
    files = []
    unzip = bool(request.form.get('unzip') in ["true", "on"])

    for uploaded_file in request.files.getlist("files"):
        if unzip and zipfile.is_zipfile(uploaded_file):
            with zipfile.ZipFile(uploaded_file, 'r') as zf:
                for info in zf.infolist():
                    name = info.filename
                    size = info.file_size
                    data = StringIO(zf.read(name))
                    if size > 0:
                        files.append(save_file(data, filename=name.split("/")[-1]))
        else:
            files.append(save_file(uploaded_file))

    return files


class File(CrudApi):
    objectmanager = observables.File

    @route("/get/id/<id>", methods=["GET"])
    @requires_permissions("read")
    def get_id(self, id):
        """Retrieves a file's content.

        :<id ObjectId corresponding to the file ObjectId
        """
        try:
            fileobj = self.objectmanager.objects.get(id=id)
            return Response(fileobj.body.stream_contents())
        except DoesNotExist:
            abort(404)

    @route("/get/hash/<hash>", methods=["GET"])
    @requires_permissions("read")
    def get_hash(self, hash):
        """Retrieves a file's content.

        :<id ObjectId corresponding to the file ObjectId
        """
        try:
            fileobj = self.objectmanager.objects.get(hashes__value=hash)
            return Response(fileobj.body.stream_contents())
        except DoesNotExist:
            abort(404)

    @route("/addfile", methods=["POST"])
    @requires_permissions('write')
    def add_file(self):
        """Adds a new File

        Create a new File from the form passed in the ``POST`` data. Each file
        should be passed in the ``files`` parameter. Multiple files can be
        added in one request.
        The file body will be stored as an AttachedFile object.

        :<file form parameter: Field containing file(s) to store
        :<unzip form parameter ([true|false]): Uncompress archive and add files
        separately
        """
        files = save_uploaded_files()

        return render_json(files)
