import logging
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import entity, task


class Malpedia_Actors(task.FeedTask):
    _defaults = {
        "frequency": timedelta(days=1),
        "name": "Malpedia",
        "description": "Gets list of malpedia actors",
        "source": "https://malpedia.caad.fkie.fraunhofer.de/",
    }

    _SOURCE: ClassVar["str"] = "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors"

    def run(self):
        response = self._make_request(self._SOURCE)
        if not response:
            return
        actors_json = response.json()
        for actor, entry in actors_json.items():
            self.analyze_entry_actor(actor, entry)

    def analyze_entry_actor(self, name_actor, entry: dict):
        intrusion_set = entity.IntrusionSet(name=entry["value"])

        if entry.get("description"):
            if intrusion_set.description:
                intrusion_set.description += "## Malpedia\n\n"
            else:
                intrusion_set.description = "## Malpedia \n\n"
            intrusion_set.description += entry["description"]
        if entry.get("meta") and entry["meta"].get("refs"):
            intrusion_set.description += "\n\n"
            intrusion_set.description += "## Malpedia External references\n\n"
            for ref in entry["meta"]["refs"]:
                intrusion_set.description += f"* {ref}\n"
        if entry.get("meta") and entry["meta"].get("synonyms"):
            intrusion_set.aliases = entry["meta"]["synonyms"]

        intrusion_set = intrusion_set.save()

        tags = []

        if intrusion_set.aliases:
            tags += intrusion_set.aliases
        tags.append(intrusion_set.name)
        tags.append(name_actor)
        try:
            intrusion_set.tag(tags)
        except Exception as e:
            logging.error(f"Error tagging actor {name_actor}: {e}")


taskmanager.TaskManager.register_task(Malpedia_Actors)
