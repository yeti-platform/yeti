import json
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.schemas import entity, task


def _format_description_from_obj(obj):
    description = ""
    if obj.get("x_mitre_deprecated"):
        description += "**DEPRECATED**\n\n"
    if obj.get("description"):
        description += obj["description"] + "\n\n"

    if not obj.get("external_references"):
        return description

    description += "## External references\n\n"
    for ref in obj["external_references"]:
        if ref.get("url"):
            description += f'* [{ref["source_name"]}]({ref["url"]})'
        else:
            description += f'* {ref["source_name"]}'
        if ref.get("description"):
            description += f': {ref["description"]}'
        description += "\n"
    return description


def _process_intrusion_set(obj):
    return entity.IntrusionSet(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        aliases=obj.get("aliases", []) + obj.get("x_mitre_aliases", []),
        created=obj["created"],
        modified=obj["modified"],
    ).save()


def _process_malware(obj):
    return entity.Malware(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
        family=obj.get("malware_types", ""),
        aliases=obj.get("aliases", []) + obj.get("x_mitre_aliases", []),
    ).save()


def _process_attack_pattern(obj):
    return entity.AttackPattern(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
        kill_chain_phases=[
            f'{phase["kill_chain_name"]}:{phase["phase_name"]}'
            for phase in obj["kill_chain_phases"]
        ],
    ).save()


def _process_course_of_action(obj):
    return entity.CourseOfAction(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
    ).save()


def _process_identity(obj):
    return entity.Identity(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
        identity_class=obj.get("identity_class"),
        sectors=obj.get("sectors", []),
        contact_information=obj.get("contact_information", ""),
    ).save()


def _process_threat_actor(obj):
    return entity.ThreatActor(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
        first_seen=obj.get("first_seen", ""),
        last_seen=obj.get("last_seen", ""),
        aliases=obj.get("aliases", []),
        threat_actor_types=obj.get("threat_actor_types", []),
    ).save()


def _process_campaign(obj):
    return entity.Campaign(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
        first_seen=obj.get("first_seen", ""),
        last_seen=obj.get("last_seen", ""),
        aliases=obj.get("aliases", []),
    ).save()


def _process_tool(obj):
    return entity.Tool(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
        tool_version=obj.get("tool_version", ""),
        aliases=obj.get("aliases", []) + obj.get("x_mitre_aliases", []),
        kill_chain_phases=[
            f'{phase["kill_chain_name"]}:{phase["phase_name"]}'
            for phase in obj.get("kill_chain_phases", [])
        ],
    ).save()


def _process_vulnerability(obj):
    return entity.Vulnerability(
        name=obj["name"],
        description=_format_description_from_obj(obj),
        created=obj["created"],
        modified=obj["modified"],
    ).save()


TYPE_FUNCTIONS = {
    "intrusion-set": _process_intrusion_set,
    "malware": _process_malware,
    "attack-pattern": _process_attack_pattern,
    "course-of-action": _process_course_of_action,
    "identity": _process_identity,
    "threat-actor": _process_threat_actor,
    "campaign": _process_campaign,
    "tool": _process_tool,
    "vulnerability": _process_vulnerability,
}


class MitreAttack(task.FeedTask):
    _defaults = {
        "name": "MitreAttack",
        "frequency": timedelta(hours=1),
        "type": "feed",
        "description": "This feed ingests the MITRE ATT&CK data.",
    }

    def run(self):
        response = self._make_request(
            "https://github.com/mitre/cti/archive/refs/tags/ATT&CK-v14.0.zip"
        )
        if not response:
            logging.info("No response: skipping MitreAttack update")
            return

        tempdir = tempfile.TemporaryDirectory()
        ZipFile(BytesIO(response.content)).extractall(path=tempdir.name)
        enterprise_attack = os.path.join(
            tempdir.name, "cti-ATT-CK-v14.0", "enterprise-attack"
        )

        object_cache = {}

        for subdir in TYPE_FUNCTIONS:
            logging.info("Processing %s", subdir)
            obj_count = 0
            if not os.path.isdir(os.path.join(enterprise_attack, subdir)):
                continue
            for file in os.listdir(os.path.join(enterprise_attack, subdir)):
                if not file.endswith(".json"):
                    continue
                with open(os.path.join(enterprise_attack, subdir, file), "r") as f:
                    data = json.load(f)
                    for item in data["objects"]:
                        if item.get("revoked"):
                            continue
                        object_cache[item["id"]] = TYPE_FUNCTIONS[item["type"]](item)
                        obj_count += 1
            logging.info("Processed %s %s objects", obj_count, subdir)

        logging.info("Processing relationships")
        rel_count = 0
        for file in os.listdir(os.path.join(enterprise_attack, "relationship")):
            if not file.endswith(".json"):
                continue
            with open(os.path.join(enterprise_attack, "relationship", file), "r") as f:
                data = json.load(f)
                for item in data["objects"]:
                    if item.get("revoked"):
                        continue
                    if item["relationship_type"] == "revoked-by":
                        continue

                    if item["source_ref"].startswith("x-mitre") or item[
                        "target_ref"
                    ].startswith("x-mitre"):
                        continue

                    source = object_cache.get(item["source_ref"])
                    target = object_cache.get(item["target_ref"])

                    if not source:
                        logging.error("Missing source for %s", item["source_ref"])
                    if not target:
                        logging.error("Missing target for %s", item["target_ref"])

                    if source and target:
                        source.link_to(
                            target,
                            item["relationship_type"],
                            item.get("description", ""),
                        )
                        rel_count += 1
        logging.info("Processed %s relationships", rel_count)


taskmanager.TaskManager.register_task(MitreAttack)
