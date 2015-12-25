from flask import request
from flask_restful import abort as restful_abort

from core.web.api.crud import CrudApi
from core.observables import Tag
from core.web.api.api import render

from core.errors import TagValidationError


class TagApi(CrudApi):
    template = "tag_api.html"
    template_single = "tag_api_single.html"
    objectmanager = Tag

    def post(self, id=None):
        if not id:
            return render(self.objectmanager.get_or_create(**request.json).info())
        else:
            try:
                tag = Tag.objects.get(id=id)
                tag.implied = [Tag.get_or_create(name=t) for t in request.json['implied'] if t.strip()]
                tag.name = request.json['name']
                tag.save()
                return render({"status": "ok"})
            except TagValidationError as e:
                restful_abort(400, error=str(e))
            except Exception as e:
                restful_abort(400, error='Must specify name and imply parameters')
