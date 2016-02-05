from flask import request, abort
from flask.ext.classy import route

from core.web.api.crud import CrudApi
from core.observables import Tag, Observable
from core.web.api.api import render

from core.errors import TagValidationError


class TagApi(CrudApi):
    template = "tag_api.html"
    template_single = "tag_api_single.html"
    objectmanager = Tag

    @route("/action/merge", methods=['POST'])
    def merge(self):
        tags = request.json['merge']
        merge_into = Tag.objects.get(name=request.json['merge_into'])
        make_dict = request.json['make_dict']

        merged = 0
        for tag in tags:
            Observable.change_all_tags(tags, merge_into.name)
            oldtag = Tag.objects.get(name=tag)
            merge_into.count += oldtag.count
            merge_into.produces += [i for i in oldtag.produces if i not in merge_into.produces and i != merge_into]
            merge_into.save()
            oldtag.delete()
            merged += 1

        if make_dict:
            merge_into.add_replaces(tags)

        return render({"merged": merged, "into": merge_into.name})

    def delete(self, id):
        tag = self.objectmanager.objects.get(id=id)
        tag.delete()
        Observable.objects(tags__name=tag.name).update(pull__tags__name=tag.name)
        return render({"status": "ok"})

    def parse_request(self, json):
        params = json
        params['produces'] = [Tag.get_or_create(name=t.strip()) for t in json['produces'].split(',') if t.strip()]
        params['replaces'] = json['replaces'].split(',')
        return params

    # @route("/", methods=['POST'])
    # def new(self):
    #     data = request.json
    #     data['produces'] = [Tag.get_or_create(name=t.strip()) for t in request.json['produces'].split(',') if t.strip()]
    #     data['replaces'] = request.json['replaces'].split(',')
    #     params = self.parse_request(request.json)
    #     return render(Tag(**data).save().info())

    def post(self, id):
        try:
            data = self.parse_request(request.json)
            t = Tag.objects.get(id=id)
            t.clean_update(**data)
            Observable.change_all_tags(t.name, data['name'])
            return render({"status": "ok"})
        except TagValidationError as e:
            abort(400, error=str(e))
        except Exception as e:
            import traceback
            traceback.print_exc()
            abort(400, error='Must specify name and produces parameters')
