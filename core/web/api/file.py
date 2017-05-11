from __future__ import unicode_literals

from flask_classy import route
from flask import request, abort
import magic

from core.web.api.crud import CrudSearchApi, CrudApi
from core import observables
from core.web.helpers import requires_permissions
from core.web.api.api import render
from core.helpers import stream_sha256
from core.database import AttachedFile

class File(CrudApi):
    objectmanager = observables.File

    @route("/addfile", methods=["POST"])
    # @requires_permissions('write')
    def add_file(self):
        """Adds a new File

        Create a new File from the JSON object passed in the ``POST`` data.
        The file body will be stored as an AttachedFile object

        :<body form parameter: Field containing file to store
        """
        body = request.files.get('body')
        value = "FILE:{}".format(stream_sha256(body))
        f = observables.File.get_or_create(value=value)
        f.mime_type = magic.from_buffer(body.read(100), mime=True)
        if body.filename not in f.filenames:
            f.filenames.append(body.filename)

        if not f.body:
            body.seek(0)
            f.body = AttachedFile.from_upload(body, force_mime=f.mime_type)

        return render(f.save())
