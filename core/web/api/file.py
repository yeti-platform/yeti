from __future__ import unicode_literals

from flask_classy import route
from flask import request, abort
import magic

from core.web.api.crud import CrudSearchApi, CrudApi
from core import observables
from core.web.helpers import requires_permissions
from core.web.api.api import render_json
from core.helpers import stream_sha256
from core.database import AttachedFile

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
            value = "FILE:{}".format(stream_sha256(uploaded_file))
            f = observables.File.get_or_create(value=value)
            f.mime_type = magic.from_buffer(uploaded_file.read(100), mime=True)
            if uploaded_file.filename not in f.filenames:
                f.filenames.append(uploaded_file.filename)

            if not f.body:
                uploaded_file.seek(0)
                f.body = AttachedFile.from_upload(uploaded_file, force_mime=f.mime_type)

            files.append(f.save())

        return render_json(files)
