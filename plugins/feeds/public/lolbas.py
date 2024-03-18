import logging
import re
from datetime import datetime, timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import entity, indicator, task
from core.schemas.observables import path


class LoLBAS(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "LoLBAS",
        "description": "Gets list of o paths, sigma rules, and Tools",
        "source": "https://lolbas-project.github.io/",
    }

    _SOURCE: ClassVar["str"] = "https://lolbas-project.github.io/api/lolbas.json"

    def run(self):
        response = self._make_request(self._SOURCE)
        if not response:
            return
        lolbas_json = response.json()
        for entry in lolbas_json:
            self.analyze_entry(entry)

    def analyze_entry(self, entry: dict):
        """Analyzes an entry as specified in the lolbas json."""
        try:
            created = datetime.strptime(entry["Created"], "%Y-%m-%d")
        except ValueError as error:
            logging.error("Error parsing lolbas %s: %s", entry["Created"], error)
            created = datetime.strptime(entry["Created"], "%Y-%d-%m")

        description = (
            f'{entry["Description"]}\n\n{self.format_commands(entry["Commands"])}'
        )
        tool = entity.Tool(
            name=entry["Name"], description=description, created=created
        ).save()
        entity_slug = entry["Name"].lower().replace(".exe", "")
        tool.tag([entity_slug, "lolbas"])

        tags = set([cmd["Category"].lower() for cmd in entry["Commands"]])
        tags.add("lolbas")
        tags.add(entity_slug)

        for filepath in entry["Full_Path"]:
            path_obj = path.Path(value=filepath["Path"]).save()
            path_obj.tag(list(tags))
            self.add_feed_context(path_obj, {"reference": entry["url"]})
            tool.link_to(
                path_obj, relationship_type="located_at", description=description
            )

        for detection in entry["Detection"] or []:
            if "Sigma" in detection:
                try:
                    self.process_sigma_rule(tool, detection)
                except Exception as error:
                    logging.error(
                        "Error processing sigma rule for %s: %s", entry["Name"], error
                    )

    def process_sigma_rule(self, tool, detection):
        """Processes a Sigma rule as specified in the lolbas json."""
        url = detection["Sigma"]
        if not url:
            return
        url = url.replace("github.com", "raw.githubusercontent.com").replace(
            "blob/", ""
        )
        sigma_yaml = self._make_request(url).text
        # extract title from yaml
        title = re.search(r"title: (.*)", sigma_yaml).group(1)
        description = re.search(r"description: (.*)", sigma_yaml).group(1)
        date = re.search(r"date: (.*)", sigma_yaml).group(1)
        date = datetime.strptime(date.strip(), "%Y/%m/%d")
        # create sigma indicator
        sigma = indicator.Sigma(
            name=title,
            description=description,
            created=date,
            pattern=sigma_yaml,
            location="filesystem",  # TODO: Actually parse YAML,
            kill_chain_phases=["payload-delivery"],
            diamond=indicator.DiamondModel.capability,
        ).save()
        sigma.link_to(
            tool,
            relationship_type="detects",
            description=f"Detects usage of {tool.name}",
        )

    def format_commands(self, commands: list[dict[str, str]]) -> str:
        formatted_command = "### Example commands:\n"
        for command in commands:
            formatted_command += f"\n* `{command['Command']}`\n"
            for key, value in command.items():
                if key not in ("Command"):
                    formatted_command += f"  * **{key}**: {value}\n"
            formatted_command += "\n"
        return formatted_command


taskmanager.TaskManager.register_task(LoLBAS)
