import json
import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.schemas import entity, task


def _format_context_from_obj(obj):
    context = {"source": "MITRE-ATT&CK", "description": ""}

    if obj.get("x_mitre_deprecated"):
        context["status"] = "deprecated"
    else:
        context["status"] = "active"
    if obj.get("description"):
        context["description"] += obj["description"] + "\n\n"

    if not obj.get("external_references"):
        return context
    context["external_references"] = ""
    for ref in obj["external_references"]:
        if ref.get("url"):
            context["external_references"] += f'* [{ref["source_name"]}]({ref["url"]})'
        else:
            context["external_references"] += f'* {ref["source_name"]}'
        if ref.get("description"):
            context["external_references"] += f': {ref["description"]}'
        context["external_references"] += "\n"
    return context


def _process_intrusion_set(obj):
    intrusion_set = entity.IntrusionSet(
        name=obj["name"],
        aliases=obj.get("aliases", []) + obj.get("x_mitre_aliases", []),
        created=obj["created"],
        modified=obj["modified"],
    ).save()
    context = _format_context_from_obj(obj)
    intrusion_set.add_context(context["source"], _format_context_from_obj(obj))
    return intrusion_set


def _process_malware(obj):
    malware = entity.Malware(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
        malware_types=obj.get("malware_types", []),
    ).save()
    context = _format_context_from_obj(obj)
    malware.add_context(context["source"], context)
    return malware


def _process_attack_pattern(obj):
    attack_pattern = entity.AttackPattern(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
        kill_chain_phases=[
            f'{phase["kill_chain_name"]}:{phase["phase_name"]}'
            for phase in obj["kill_chain_phases"]
        ],
        aliases=[list(
            filter(
                lambda x: x["source_name"] == "mitre-attack",
                obj['external_references'],
            )
        )[0]["external_id"]],
    ).save()
    context = _format_context_from_obj(obj)
    attack_pattern.add_context(context["source"], context)
    return attack_pattern


def _process_course_of_action(obj):
    course_of_action = entity.CourseOfAction(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
    )
    context = _format_context_from_obj(obj)
    course_of_action.add_context(context["source"], context)
    return course_of_action.save()


def _process_identity(obj):
    identity = entity.Identity(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
        identity_class=obj.get("identity_class"),
        sectors=obj.get("sectors", []),
        contact_information=obj.get("contact_information", ""),
    ).save()
    context = _format_context_from_obj(obj)
    identity.add_context(context["source"], context)
    return identity


def _process_threat_actor(obj):
    threat_actor = entity.ThreatActor(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
        first_seen=obj.get("first_seen", ""),
        last_seen=obj.get("last_seen", ""),
        aliases=obj.get("aliases", []),
        threat_actor_types=obj.get("threat_actor_types", []),
    ).save()
    context = _format_context_from_obj(obj)
    threat_actor.add_context(context["source"], context)
    return threat_actor


def _process_campaign(obj):
    campaign = entity.Campaign(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
        first_seen=obj.get("first_seen", ""),
        last_seen=obj.get("last_seen", ""),
        aliases=obj.get("aliases", []),
    ).save()
    context = _format_context_from_obj(obj)
    campaign.add_context(context["source"], context)
    return campaign


def _process_tool(obj):
    tool = entity.Tool(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
        tool_version=obj.get("tool_version", ""),
        aliases=obj.get("aliases", []) + obj.get("x_mitre_aliases", []),
        kill_chain_phases=[
            f'{phase["kill_chain_name"]}:{phase["phase_name"]}'
            for phase in obj.get("kill_chain_phases", [])
        ],
    ).save()
    context = _format_context_from_obj(obj)
    tool.add_context(context["source"], context)
    return tool


def _process_vulnerability(obj):
    vulnerabilty = entity.Vulnerability(
        name=obj["name"],
        created=obj["created"],
        modified=obj["modified"],
    ).save()
    context = _format_context_from_obj(obj)
    vulnerabilty.add_context(context["source"], context)
    return vulnerabilty


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

_VERSION = "v15.1"


class MitreAttack(task.FeedTask):
    _defaults = {
        "name": "MitreAttack",
        "frequency": timedelta(days=10),
        "type": "feed",
        "description": "This feed ingests the MITRE ATT&CK data.",
    }

    def run(self):
        response = self._make_request(
            f"https://github.com/mitre/cti/archive/refs/tags/ATT&CK-{_VERSION}.zip"
        )  # url is fixed because the code works with this version only
        if not response:
            logging.info("No response: skipping MitreAttack update")
            return

        tempdir = tempfile.TemporaryDirectory()
        ZipFile(BytesIO(response.content)).extractall(path=tempdir.name)
        enterprise_attack = os.path.join(
            tempdir.name, f"cti-ATT-CK-{_VERSION}", "enterprise-attack"
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
                        object_temp = TYPE_FUNCTIONS[subdir](item)
                        tags = item.get("aliases", [item["name"]])
                        object_temp.tag(tags)
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
