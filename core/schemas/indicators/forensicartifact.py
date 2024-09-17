import io
import logging
import re
from typing import ClassVar, Literal

import yaml
from artifacts import definitions, reader, writer
from artifacts import errors as artifacts_errors
from pydantic import field_validator

from core.schemas import indicator
from core.schemas.indicators import regex


class ForensicArtifact(indicator.Indicator):
    """Represents a Forensic Artifact

    As defined in https://github.com/ForensicArtifacts/artifacts
    """

    _type_filter: ClassVar[str] = indicator.IndicatorType.forensicartifact
    type: Literal[indicator.IndicatorType.forensicartifact] = indicator.IndicatorType.forensicartifact

    sources: list[dict] = []
    aliases: list[str] = []
    supported_os: list[str] = []

    def match(self, value: str) -> indicator.IndicatorMatch | None:
        raise NotImplementedError

    @field_validator("pattern")
    @classmethod
    def validate_artifact(cls, value) -> str:
        artifact_reader = reader.YamlArtifactsReader()
        try:
            list(artifact_reader.ReadFileObject(io.StringIO(value)))
        except artifacts_errors.FormatError as error:
            raise ValueError(f"Invalid ForensicArtifact YAML: {error}")
        return value

    @classmethod
    def from_yaml_string(
        cls, yaml_string: str, update_parents: bool = False
    ) -> list["ForensicArtifact"]:
        artifact_reader = reader.YamlArtifactsReader()
        artifact_writer = writer.YamlArtifactsWriter()

        artifacts_dict = {}

        for definition in artifact_reader.ReadFileObject(io.StringIO(yaml_string)):
            definition_dict = definition.AsDict()
            definition_dict["description"] = definition_dict.pop("doc")
            if definition.urls:
                definition_dict["description"] += "\n\nURLs:\n"
                definition_dict["description"] += " ".join(
                    [f"* {url}\n" for url in definition.urls]
                )
            definition_dict["pattern"] = artifact_writer.FormatArtifacts([definition])
            definition_dict["location"] = "host"
            definition_dict["diamond"] = indicator.DiamondModel.victim
            definition_dict["relevant_tags"] = [definition_dict["name"]]
            forensic_indicator = cls(**definition_dict).save()
            artifacts_dict[definition.name] = forensic_indicator

        if update_parents:
            for artifact in artifacts_dict.values():
                artifact.update_parents(artifacts_dict)

        return list(artifacts_dict.values())

    def update_yaml(self):
        artifact_reader = reader.YamlArtifactsReader()
        definition_dict = next(
            artifact_reader.ReadFileObject(io.StringIO(self.pattern))
        ).AsDict()
        definition_dict["doc"] = self.description.split("\n\nURLs:")[0]
        definition_dict["name"] = self.name
        definition_dict["supported_os"] = self.supported_os
        self.pattern = yaml.safe_dump(definition_dict)

    def update_parents(self, artifacts_dict: dict[str, "ForensicArtifact"]) -> None:
        for source in self.sources:
            if not source["type"] == definitions.TYPE_INDICATOR_ARTIFACT_GROUP:
                continue
            for child_name in source["attributes"]["names"]:
                child = artifacts_dict.get(child_name)
                if not child:
                    logging.error(f"Missing child {child_name} for {self.name}")
                    continue

                add_tags = set(self.relevant_tags + [self.name])
                child.relevant_tags = list(add_tags | set(child.relevant_tags))
                child.save()
                child.link_to(
                    self,
                    "included in",
                    f"Included in ForensicArtifact definition for {self.name}",
                )

    def save_indicators(self, create_links: bool = False):
        indicators = []
        for source in self.sources:
            if source["type"] == definitions.TYPE_INDICATOR_FILE:
                for path in source["attributes"]["paths"]:
                    # TODO: consider using https://github.com/log2timeline/dfvfs/blob/main/dfvfs/lib/glob2regex.py
                    pattern = ARTIFACT_INTERPOLATION_RE.sub("*", path)
                    pattern = re.escape(pattern).replace("\\*", ".*")
                    # Account for different path separators
                    pattern = re.sub(r"\\\\", r"[\\|/]", pattern)
                    regex_indicator = regex.Regex.find(name=path)
                    if not regex_indicator:
                        try:
                            regex_indicator = regex.Regex(
                                name=path,
                                pattern=pattern,
                                location="filesystem",
                                diamond=indicator.DiamondModel.victim,
                                relevant_tags=self.relevant_tags,
                            ).save()
                            indicators.append(regex_indicator)
                        except Exception as error:
                            logging.error(
                                f"Failed to create indicator for {path} (was: {source['attributes']['paths']}): {error}"
                            )
                            continue

                    else:
                        regex_indicator.relevant_tags = list(
                            set(regex_indicator.relevant_tags + self.relevant_tags)
                        )
                        regex_indicator.save()
        if source["type"] == definitions.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY:
            for key in source["attributes"]["keys"]:
                pattern = re.sub(r"\\\*$", "", key)
                pattern = ARTIFACT_INTERPOLATION_RE.sub("*", pattern)
                pattern = re.escape(pattern)
                pattern = pattern.replace(
                    "HKEY_USERS\\\\\\*",
                    r"(HKEY_USERS\\*|HKEY_CURRENT_USER)",
                )
                pattern = pattern.replace("*", r".*").replace("?", r".")
                if "CurrentControlSet" in pattern:
                    pattern = pattern.replace(
                        "CurrentControlSet", "(CurrentControlSet|ControlSet[0-9]+)"
                    )
                    pattern = pattern.replace("HKEY_LOCAL_MACHINE\\\\System\\\\", "")

                regex_indicator = regex.Regex.find(name=key)

                if not regex_indicator:
                    try:
                        regex_indicator = regex.Regex(
                            name=key,
                            pattern=pattern,
                            location="registry",
                            diamond=indicator.DiamondModel.victim,
                            relevant_tags=self.relevant_tags,
                        ).save()
                        indicators.append(regex_indicator)
                    except Exception as error:
                        logging.error(
                            f"Failed to create indicator for {key} (was: {source['attributes']['keys']}): {error}"
                        )
                        continue
                else:
                    regex_indicator.relevant_tags = list(
                        set(regex_indicator.relevant_tags + self.relevant_tags)
                    )
                    regex_indicator.save()
        if create_links:
            for indicator_obj in indicators:
                indicator_obj.link_to(self, "indicates", f"Indicates {indicator_obj.name}")
        return indicators


ARTIFACT_INTERPOLATION_RE = re.compile(r"%%[a-z._]+%%")
ARTIFACT_INTERPOLATION_RE_HKEY_USERS = re.compile(r"HKEY_USERS\\%%users.sid%%")
