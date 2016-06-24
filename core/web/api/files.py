from flask import request, abort, make_response, send_file, url_for
from flask_classy import FlaskView

from core.database import AttachedFile
from core.web.helpers import get_object_or_404
from core.web.api.api import render


class Files(FlaskView):
    def post(self):
        if 'file' not in request.files:
            abort(400)

        f = AttachedFile.from_upload(request.files['file'])
        return render({'filename': url_for('api.Files:get', id=f.id)})

    def get(self, id):
        f = get_object_or_404(AttachedFile, id=id)
        return make_response(send_file(f.filepath))
