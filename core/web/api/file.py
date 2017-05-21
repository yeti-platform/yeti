from __future__ import unicode_literals

from flask_classy import route
from flask import request, abort
import magic
from StringIO import StringIO
import zipfile

from core.web.api.crud import CrudSearchApi, CrudApi
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

class File(CrudApi):
    objectmanager = observables.File

    @route("/addfile", methods=["POST"])
    @requires_permissions('write')
    def add_file(self):
        """Adds a new File

        Create a new File from the form passed in the ``POST`` data. Each file
        should be passed in the ``files`` parameter. Multiple files can be
        added in one request.
        The file body will be stored as an AttachedFile object

        :<file form parameter: Field containing file(s) to store
        """
        files = []
        for uploaded_file in request.files.getlist("files"):
            unzip = bool(request.form.get('unzip') == "true")
            if unzip:
                if zipfile.is_zipfile(uploaded_file):
                    with zipfile.ZipFile(uploaded_file, 'r') as zf:
                        for info in zf.infolist():
                            name = info.filename
                            size = info.file_size
                            data = StringIO(zf.read(name))
                            if size > 0:
                                files.append(save_file(data, filename=name.split("/")[-1]))
                else:
                    return (render_json({"error": "Invalid Zipfile"}), 400)

            else:
                files.append(save_file(uploaded_file))

        return render_json(files)
