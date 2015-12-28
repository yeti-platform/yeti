from flask import request
from flask_restful import abort as restful_abort
from flask_restful import Resource

from core.web.api.crud import CrudApi
from core.observables import Tag, Observable
from core.web.api.api import render

from core.errors import TagValidationError


class TagActionApi(Resource):
    def post(self, action=None):
        if action == 'merge':
            print request.json
            tags = request.json['merge']
            merge_into = Tag.objects.get(name=request.json['merge_into'])

            merged = 0
            for tag in tags:
                Observable.objects(tags__name=tag).modify(set__tags__S__name=merge_into.name)
                oldtag = Tag.objects.get(name=tag)
                merge_into.count += oldtag.count
                merge_into.implied += [i for i in oldtag.implied if i not in merge_into.implied and i != merge_into]
                merge_into.save()
                oldtag.delete()
                merged += 1

            return render({"merged": merged, "into": merge_into.name})



class TagApi(CrudApi):
    template = "tag_api.html"
    template_single = "tag_api_single.html"
    objectmanager = Tag

    def post(self, id=None):
        if not id:
            data = request.json
            data['implied'] = [Tag.get_or_create(name=t.strip()) for t in request.json['implied'].split(',') if t.strip()]
            return render(Tag(**data).save().info())
        else:
            try:
                data = request.json
                data['implied'] = [Tag.get_or_create(name=t.strip()) for t in request.json['implied'].split(',') if t.strip()]
                Tag.objects(id=id).update(**data)
                return render({"status": "ok"})
            except TagValidationError as e:
                restful_abort(400, error=str(e))
            except Exception as e:
                restful_abort(400, error='Must specify name and implied parameters')
