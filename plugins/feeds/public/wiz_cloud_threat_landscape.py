import logging
import re
from datetime import timedelta
from typing import ClassVar

import requests

from core import taskmanager
from core.schemas import task
from core.schemas.entity import AttackPattern, Campaign, IntrusionSet, Tool

VALUE_PROPERTIES = [
    "tags",
    "attribution",
    "mitre tactic",
    "initial access",
    "impact",
    "type",
]
TITLED_PROPERTIES = [
    "incidents",
    "actors",
    "observed techniques",
    "observed tools",
    "targeted technologies",
    "techniques",
]


def _get_build_id():
    response = requests.get("https://threats.wiz.io")
    if response.status_code != 200:
        return None
    p = re.compile('"buildId":"(.*?(?="))"')
    m = p.search(response.text)
    if m:
        return m.group(1)
    else:
        return None


def _get_properties(build_id: str, property: str) -> dict:
    base_uri = f"https://threats.wiz.io/_next/data/{build_id}/all-{property}"
    main_endpoint = f"{base_uri}.json?page=all-{property}"
    response = requests.get(main_endpoint)
    properties = dict()
    if response.status_code != 200:
        return properties
    data = response.json()
    for record in data["pageProps"]["records"]["block"]:
        if not record.startswith(f"all-{property}-"):
            continue
        property_id = record.replace(f"all-{property}-", "")
        property_endpoint = (
            f"{base_uri}/{property_id}.json?page=all-{property}&page={property_id}"
        )
        response = requests.get(property_endpoint)
        if response.status_code != 200:
            continue
        data = response.json()
        blocks = data.get("pageProps", {}).get("records", {}).get("block", {})
        property_key = f"all-{property}-{property_id}"
        if not blocks.get(property_key, {}):
            continue
        property_url = data["pageProps"]["head"]["url"].strip()
        property_name = data["pageProps"]["head"]["title"].strip()
        logging.debug(f"Importing {property}: {property_name}")
        property_details = _get_property_details(blocks, property_key)
        property_details["url"] = property_url
        properties[property_name] = property_details
    return properties


def _get_property_details(blocks: dict, property_key: str) -> dict:
    property_data = blocks[property_key]
    property_to_name = {
        property["property"]: property["name"].lower()
        for property in property_data["propertySort"]
    }
    properties = dict()
    for property_id, property in property_data["propertyValues"].items():
        if property_id not in property_to_name:
            continue
        property_name = property_to_name[property_id]
        if property_name == "mitre technique":
            properties[property_name] = [
                technique[0] for technique in property if technique
            ]
        if property_name == "aliases":
            properties[property_name] = property[0][0].split(",")
        elif property_name in VALUE_PROPERTIES:
            properties[property_name] = [prop["value"] for prop in property]
        elif property_name in TITLED_PROPERTIES:
            properties[property_name] = [
                data[1][0][1]["title"][0][0]
                for data in property
                if data and data[0] != ","
            ]
        elif property_name == "references":
            properties[property_name] = [
                reference["fileName"].strip() for reference in property
            ]
    description = ""
    for child in property_data.get("children", []):
        child_data = blocks.get(child)
        if not child_data:
            continue
        content = ""
        titles = child_data.get("title", [])
        if not titles:
            continue
        for item in titles:
            for sub_item in item:
                if sub_item:
                    content += f"{sub_item} "
        content = content.strip()
        content_type = child_data.get("type")
        if content_type == "text":
            description += f"{content}\n"
        elif content_type == "bulleted_list":
            description += f"* {content}\n"
    properties["description"] = description
    return properties


class WizCloudThreatLandscape(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "WizCloudThreatLandscape",
        "description": "This feed imports campaigns, tools, techniques and intrusion sets seen cloud threats",
    }

    _SOURCE: ClassVar["str"] = "https://threats.wiz.io/"

    def run(self):
        self._intrusion_sets = {}
        self._techniques = {}
        self._tools = {}
        self._campaigns = {}
        build_id = _get_build_id()
        if not build_id:
            return False
        self._create_intrusion_sets(build_id)
        self._create_attack_patterns(build_id)
        self._create_tools(build_id)
        self._create_campaigns(build_id)
        self._create_intrusion_sets_relationships()
        self._create_attack_patterns_relationships()
        self._create_tools_relationships()
        self._create_campaigns_relationships()

    def _create_intrusion_sets_relationships(self):
        # attributed-to
        logging.info("Processing intrusion-set relationships")
        count = 0
        for name, properties in self._intrusion_sets.items():
            intrusion_set = IntrusionSet.find(name=name)
            if not intrusion_set:
                continue
            for incident in properties.get("incidents", []):
                campaign = Campaign.find(name=incident)
                if not campaign:
                    continue
                count += 1
                campaign.link_to(intrusion_set, "attributed-to", "")
        logging.info(f"Processed {count} intrusion-set relationships")

    def _create_attack_patterns_relationships(self):
        logging.info("Processing attack-pattern relationships")
        count = 0
        for name, properties in self._techniques.items():
            attack_pattern = AttackPattern.find(name=name)
            if not attack_pattern:
                continue
            for name in properties.get("incidents", []):
                campaign = Campaign.find(name=name)
                if not campaign:
                    continue
                count += 1
                campaign.link_to(attack_pattern, "uses", "")
        logging.info(f"Processed {count} attack-pattern relationships")

    def _create_tools_relationships(self):
        logging.info("Processing tool relationships")
        count = 0
        for name, properties in self._tools.items():
            tool = Tool.find(name=name)
            if not tool:
                continue
            for technique in properties.get("techniques", []):
                attack_pattern = AttackPattern.find(name=technique)
                if not attack_pattern:
                    continue
                count += 1
                tool.link_to(attack_pattern, "uses", "")
            for incident in properties.get("incidents", []):
                campaign = Campaign.find(name=incident)
                if not campaign:
                    continue
                count += 1
                campaign.link_to(tool, "uses", "")
        logging.info(f"Processed {count} tool relationships")

    def _create_campaigns_relationships(self):
        logging.info("Processing campaign relationships")
        count = 0
        for name, properties in self._campaigns.items():
            campaign = Campaign.find(name=name)
            if not campaign:
                continue
            for technique in properties.get("observed techniques", []):
                attack_pattern = AttackPattern.find(name=technique)
                if not attack_pattern:
                    continue
                count += 1
                campaign.link_to(attack_pattern, "uses", "")
            for tool_name in properties.get("observed tools", []):
                tool = Tool.find(name=tool_name)
                if not tool:
                    continue
                count += 1
                campaign.link_to(tool, "uses", "")
            for actor in properties.get("actors", []):
                intrusion_set = IntrusionSet.find(name=actor)
                if not intrusion_set:
                    continue
                count += 1
                campaign.link_to(intrusion_set, "attributed-to", "")
        logging.info(f"Processed {count} campaign relationships")

    def _format_description(self, properties):
        description = properties.get("description", "")
        if properties.get("initial access"):
            description += "\n\n**Initial access:**"
            for initial_access in properties.get("initial access", []):
                description += f"\n* {initial_access}"
        if properties.get("impact"):
            description += "\n\n**Impact:**"
            for impact in properties.get("impact", []):
                description += f"\n* {impact}"
        if properties.get("references"):
            description += "\n\n**References:**"
            for reference in properties.get("references", []):
                description += f"\n* [{reference}]({reference})"
        source = properties.get("url")
        description += f"\n\n**Source:** {source}\n\n"
        return description

    def _create_intrusion_sets(self, build_id):
        logging.info("Processing intrusion-set")
        self._intrusion_sets = _get_properties(build_id, "actors")
        for name, properties in self._intrusion_sets.items():
            aliases = properties.get("aliases", [])
            description = self._format_description(properties)
            entity = IntrusionSet(
                name=name, aliases=aliases, description=description
            ).save()
            tags = properties.get("tags", [])
            tags.append("cloud")
            entity.tag(tags)
        logging.info(f"Processed {len(self._intrusion_sets)} intrusion-set objects")

    def _create_attack_patterns(self, build_id):
        logging.info("Processing attack-pattern")
        self._techniques = _get_properties(build_id, "techniques")
        for name, properties in self._techniques.items():
            entity = AttackPattern.find(name=name)
            if not entity:
                description = self._format_description(properties)
                entity = AttackPattern(name=name, description=description).save()
            kill_chain_phases = set(entity.kill_chain_phases)
            for mitre_technique in properties.get("mitre tactic", []):
                m = re.search("(.*?(?=\())", mitre_technique)
                if m:
                    kill_chain_phase = "mitre-attack:" + m.group(1).strip().lower()
                    kill_chain_phases.add(kill_chain_phase)
            entity.kill_chain_phases = list(kill_chain_phases)
            entity.save()
            tags = properties.get("tags", [])
            entity.tag(tags)
        logging.info(f"Processed {len(self._techniques)} attack-pattern objects")

    def _create_tools(self, build_id):
        logging.info("Processing attack")
        self._tools = _get_properties(build_id, "tools")
        for name, properties in self._tools.items():
            entity = Tool.find(name=name)
            if not entity:
                description = self._format_description(properties)
                entity = Tool(name=name, description=description).save()
            tags = properties.get("tags", [])
            entity.tag(tags)
        logging.info(f"Processed {len(self._tools)} tool objects")

    def _create_campaigns(self, build_id):
        logging.info("Processing campaign")
        self._campaigns = _get_properties(build_id, "incidents")
        for name, properties in self._campaigns.items():
            entity = Campaign.find(name=name)
            if not entity:
                logging.info(f"Creating campaign {name}")
                description = self._format_description(properties)
                entity = Campaign(name=name, description=description).save()
            tags = properties.get("tags", [])
            entity.tag(tags)
        logging.info(f"Processed {len(self._campaigns)} campaign objects")


taskmanager.TaskManager.register_task(WizCloudThreatLandscape)
