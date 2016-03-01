from flask import request, abort
from flask.ext.classy import route

from core.web.api.crud import CrudApi
from core import observables
from core.web.api.api import render

from core.errors import TagValidationError


class Tag(CrudApi):
    template = "tag_api.html"
    template_single = "tag_api_single.html"
    objectmanager = observables.Tag

    @route("/merge", methods=['POST'])
    def merge(self):
        tags = request.json['merge']
        merge_into = self.objectmanager.objects.get(name=request.json['merge_into'])
        make_dict = request.json['make_dict']

        merged = 0
        observables.Observable.change_all_tags(tags, merge_into.name)

        for tag in tags:
            oldtag = self.objectmanager.objects.get(name=tag)
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
        observables.Observable.objects(tags__name=tag.name).update(pull__tags__name=tag.name)
        return render({"status": "ok"})

    def parse_request(self, json):
        params = json
        params['produces'] = [self.objectmanager.get_or_create(name=t.strip()) for t in json['produces'].split(',') if t.strip()]
        params['replaces'] = json['replaces'].split(',')
        return params

    def post(self, id):
        try:
            data = self.parse_request(request.json)
            t = self.objectmanager.objects.get(id=id)
            oldname = t.name
            t.clean_update(**data)
            # we override this so change_all_tags can be called
            if data['name'] != t.name:
                observables.Observable.change_all_tags(oldname, data['name'])
            return render({"status": "ok"})
        except TagValidationError as e:
            abort(400)
        except Exception as e:
            import traceback
            traceback.print_exc()
            abort(400)
