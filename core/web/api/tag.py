from __future__ import unicode_literals

from flask import request, abort
from flask_classy import route

from core.web.api.crud import CrudApi, CrudSearchApi
from core import observables
from core.web.api.api import render
from core.errors import TagValidationError
from core.web.helpers import requires_permissions


class Tag(CrudApi):
    objectmanager = observables.Tag

    @route("/merge", methods=['POST'])
    @requires_permissions('write')
    def merge(self):
        """Merge one or more tags

        Merge one or more tags into a single tag. This is useful for
        replacing one or several tags with other tags.

        :<json [String] merge: Array of Strings (tag names) representing tags to be merged.
        :<json String merge_into: The tag to merge into
        :<json boolean make_dict: Create a Tag dictionary out of this merge.
                                    In the future, tags included in the ``merge``
                                    object will be automatically
                                    replaced by the tag specified in ``merge_into``.
        """
        tags = request.json['merge']
        merge_into = self.objectmanager.objects.get(
            name=request.json['merge_into'])
        make_dict = request.json['make_dict']

        merged = 0
        observables.Observable.change_all_tags(tags, merge_into.name)

        for tag in tags:
            oldtag = self.objectmanager.objects.get(name=tag)
            merge_into.count += oldtag.count
            merge_into.produces += [
                i for i in oldtag.produces
                if i not in merge_into.produces and i != merge_into
            ]
            merge_into.save()
            oldtag.delete()
            merged += 1

        if make_dict:
            merge_into.add_replaces(tags)

        return render({"merged": merged, "into": merge_into.name})

    @requires_permissions('write')
    def delete(self, id):
        """Deletes a Tag

        Also remove the tag from any tagged elements.

        :query ObjectID id: Element ID
        :>json string deleted: The deleted element's ObjectID
        """
        tag = self.objectmanager.objects.get(id=id)
        tag.delete()
        observables.Observable.objects(tags__name=tag.name).update(
            pull__tags__name=tag.name)
        return render({"deleted": id})

    def _parse_request(self, json):
        params = json
        params['produces'] = [
            self.objectmanager.get_or_create(name=t.strip())
            for t in json['produces']
            if t.strip()
        ]
        params['replaces'] = json['replaces']
        return params

    @requires_permissions('write')
    def post(self, id):
        """Create a new Tag

        Edit an existing Tag according to the JSON object passed in the ``POST`` data.
        If the name of a tag is changed, it will repeat the change in all Observables associated
        with this tag.

        :query ObjectID id: Element ID
        :<json object params: JSON object containing fields to set
        """
        try:
            data = self._parse_request(request.json)
            t = self.objectmanager.objects.get(id=id)
            oldname = t.name
            data['default_expiration'] = int(data['default_expiration'])
            t.clean_update(**data)
            # we override this so change_all_tags can be called
            if data['name'] != oldname:
                observables.Observable.change_all_tags(oldname, data['name'])
            return render({"status": "ok"})
        except TagValidationError:
            abort(400)
        except Exception:
            import traceback
            traceback.print_exc()
            abort(400)

class TagSearch(CrudSearchApi):
    objectmanager = observables.Tag
