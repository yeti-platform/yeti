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
        for malware_name, entry in families_json.items():
            self.analyze_entry(malware_name, entry)

    def analyze_entry(self, malware_name: str, entry: dict):
        """Analyzes an entry as specified in the malpedia json."""

        if not entry.get("common_name"):
            return

        m = entity.Malware.find(name=entry["common_name"])
        if not m:
            m = entity.Malware(name=entry["common_name"])

        m.aliases = entry.get("aliases", [])
        refs = entry.get("urls", [])
        context = {
            "source": "Malpedia",
            "description": entry.get("description", ""),
            "external_references": "\n* " + "\n* ".join(refs),
        }
        m.family = entry.get("type", "")
        m = m.save()
        m.add_context(context["source"], context)
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
        tags.append(malware_name)
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
        for actor_name, entry in actors_json.items():
            self.analyze_entry(actor_name, entry)

    def analyze_entry(self, actor_name: str, entry: dict):
        intrusion_set = entity.IntrusionSet.find(name=entry["value"])
        if not intrusion_set:
            intrusion_set = entity.IntrusionSet(name=entry["value"])

        refs = entry.get("meta", {}).get("refs", [])
        context = {
            "source": "Malpedia",
            "description": entry.get("description", ""),
            "external_references": "\n* " + "\n* ".join(refs),
        }

        synonyms = entry.get("meta", {}).get("synonyms", [])

        if synonyms:
            intrusion_set.aliases = synonyms

        intrusion_set = intrusion_set.save()
        intrusion_set.add_context(context["source"], context)
        tags = []

        if intrusion_set.aliases:
            tags += intrusion_set.aliases
        tags.append(intrusion_set.name)
        tags.append(actor_name)
        try:
            intrusion_set.tag(tags)
        except Exception as e:
            logging.error(f"Error tagging IntrusionSet {intrusion_set.name}: {e}")


taskmanager.TaskManager.register_task(MalpediaActors)
taskmanager.TaskManager.register_task(MalpediaMalware)
