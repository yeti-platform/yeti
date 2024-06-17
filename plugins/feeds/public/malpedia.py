import logging
from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import entity, task


class MalpediaMalware(task.FeedTask):
    _defaults = {
        "frequency": timedelta(days=1),
        "name": "Malpedia Malware",
        "description": "Gets list of Malpedia malware",
        "source": "https://malpedia.caad.fkie.fraunhofer.de/",
    }

    _SOURCE: ClassVar["str"] = (
        "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"
    )

    def run(self):
        response = self._make_request(self._SOURCE)
        if not response:
            return
        families_json = response.json()
        for sign_mal, entry in families_json.items():
            self.analyze_entry(sign_mal, entry)

    def analyze_entry(self, name_malware, entry: dict):
        """Analyzes an entry as specified in the malpedia json."""

        if not entry.get("common_name"):
            return

        m = entity.Malware.find(name=entry["common_name"])
        if not m:
            m = entity.Malware(name=entry["common_name"])

        m.aliases = entry.get("aliases", [])
        context = {"source": "Malpedia","description":"" ,"External references":"* "}
        context["description"] += entry.get("description", "")
        context["External references"] += "\n* ".join(entry.get("urls", []))
        m.family = entry.get("type", "")
        m = m.save()
        m.add_context(self.name, context)
        attributions = entry.get("attribution", [])
        for attribution in attributions:
            intrusion_set = entity.IntrusionSet.find(name=attribution)
            if not intrusion_set:
                intrusion_set = entity.IntrusionSet(name=attribution).save()
            intrusion_set.link_to(m, "uses", "Malpedia")

        tags = []
        if m.aliases:
            tags += m.aliases
        tags.append(m.name)
        tags.append(name_malware)
        m.tag(tags)


class MalpediaActors(task.FeedTask):
    _defaults = {
        "frequency": timedelta(days=1),
        "name": "Malpedia Actors",
        "description": "Gets list of Malpedia actors",
        "source": "https://malpedia.caad.fkie.fraunhofer.de/",
    }

    _SOURCE: ClassVar["str"] = "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors"

    def run(self):
        response = self._make_request(self._SOURCE)
        if not response:
            return
        actors_json = response.json()
        for actor, entry in actors_json.items():
            self.analyze_entry(actor, entry)

    def analyze_entry(self, name_actor, entry: dict):
        intrusion_set = entity.IntrusionSet.find(name=entry["value"])
        if not intrusion_set:
            intrusion_set = entity.IntrusionSet(name=entry["value"])

        context = {"source": "Malpedia","description":"", "External references":"* "}
        context["description"] += entry.get("description", "")
        context["External references"] += "\n* ".join(
            entry.get("meta", {}).get("refs", [])
        )

        synonyms = entry.get("meta", {}).get("synonyms", [])

        if synonyms:
            intrusion_set.aliases = synonyms

        intrusion_set = intrusion_set.save()
        intrusion_set.add_context(self.name, context)
        tags = []

        if intrusion_set.aliases:
            tags += intrusion_set.aliases
        tags.append(intrusion_set.name)
        tags.append(name_actor)
        try:
            intrusion_set.tag(tags)
        except Exception as e:
            logging.error(f"Error tagging actor {name_actor}: {e}")


taskmanager.TaskManager.register_task(MalpediaActors)
taskmanager.TaskManager.register_task(MalpediaMalware)
