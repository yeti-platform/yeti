from bson.json_util import loads

from flask import request, abort, make_response, send_file, url_for
from flask_classy import FlaskView

from core.database import AttachedFile
from core.web.helpers import get_object_or_404
from core.web.api.api import render


class AttachedFiles(FlaskView):
    def post(self):
        if "file" in request.files:
            f = AttachedFile.from_upload(request.files["file"])
        else:
            data = loads(request.data)
            if "file" in data:
                f = AttachedFile.from_upload(data["file"])
            else:
                abort(400)

        return render({"filename": url_for("api.AttachedFiles:get", id=f.id)})

    def get(self, id):
        f = get_object_or_404(AttachedFile, id=id)
        return make_response(send_file(f.filepath))
