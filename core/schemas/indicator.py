import datetime
import io
import logging
import re
from enum import Enum
from typing import Annotated, ClassVar, Literal, Type, Union

import yaml
from artifacts import definitions, reader, writer
from artifacts import errors as artifacts_errors
from pydantic import BaseModel, Field, PrivateAttr, computed_field, field_validator

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiTagModel

from idstools import rule


def future():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=DEFAULT_INDICATOR_VALIDITY_DAYS
    )


DEFAULT_INDICATOR_VALIDITY_DAYS = 30


class IndicatorType(str, Enum):
    regex = "regex"
    yara = "yara"
    sigma = "sigma"
    query = "query"
    suricata = "suricata"
    forensicartifact = "forensicartifact"


class IndicatorMatch(BaseModel):
    name: str
    match: str


class DiamondModel(Enum):
    adversary = "adversary"
    capability = "capability"
    infrastructure = "infrastructure"
    victim = "victim"


class Indicator(YetiTagModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "indicators"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["indicator"] = "indicator"

    name: str
    type: str
    description: str = ""
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    valid_from: datetime.datetime = Field(default_factory=now)
    valid_until: datetime.datetime = Field(default_factory=future)

    pattern: str = Field(min_length=1)
    location: str = ""
    diamond: DiamondModel
    kill_chain_phases: list[str] = []
    relevant_tags: list[str] = []

    @computed_field(return_type=Literal["indicator"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "IndicatorTypes":
        if cls._type_filter:
            loader = TYPE_MAPPING[cls._type_filter]
        elif object["type"] in TYPE_MAPPING:
            loader = TYPE_MAPPING[object["type"]]
        else:
            raise ValueError("Attempted to instantiate an undefined indicator type.")
        return loader(**object)

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError

    @classmethod
    def search(cls, observables: list[str]) -> list[tuple[str, "Indicator"]]:
        indicators = list(Indicator.list())
        for observable in observables:
            for indicator in indicators:
                try:
                    if indicator.match(observable):
                        yield observable, indicator
                except NotImplementedError as error:
                    logging.error(
                        f"Indicator type {indicator.type} has not implemented match(): {error}"
                    )


class Regex(Indicator):
    _type_filter: ClassVar[str] = IndicatorType.regex
    _compiled_pattern: re.Pattern | None = PrivateAttr(None)
    type: Literal["regex"] = IndicatorType.regex

    @property
    def compiled_pattern(self):
        if not self._compiled_pattern:
            self._compiled_pattern = re.compile(self.pattern)
        return self._compiled_pattern

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, value) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError(f"Invalid regex pattern: {error}")
        return value

    def match(self, value: str) -> IndicatorMatch | None:
        result = self.compiled_pattern.search(value)
        if result:
            return IndicatorMatch(name=self.name, match=result.group())
        return None


class Query(Indicator):
    """Represents a query that can be sent to another system."""

    _type_filter: ClassVar[str] = IndicatorType.query
    type: Literal["query"] = IndicatorType.query

    query_type: str
    target_systems: list[str] = []

    def match(self, value: str) -> IndicatorMatch | None:
        return None


class Yara(Indicator):
    """Represents a Yara rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = IndicatorType.yara
    type: Literal["yara"] = IndicatorType.yara

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError

class Suricata(Indicator):
    """Represents a Suricata rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = IndicatorType.suricata
    type: Literal["suricata"] = IndicatorType.suricata

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError
    
    @classmethod
    def validate_rules(cls) -> bool:
        try:
            rule.parse(cls.pattern)
            return True
        except Exception as e:
            logging.error(f"invalid {cls.pattern} {e}")
            return False
    
    def parse(self) -> rule.Rule | None:
        try:
            return rule.parse(self.pattern)
        except Exception as e:
            logging.error(f" Error parsing {self.pattern} {e}")
        
class Sigma(Indicator):
    """Represents a Sigma rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = IndicatorType.sigma
    type: Literal["sigma"] = IndicatorType.sigma

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError


class ForensicArtifact(Indicator):
    """Represents a Forensic Artifact

    As defined in https://github.com/ForensicArtifacts/artifacts
    """

    _type_filter: ClassVar[str] = IndicatorType.forensicartifact
    type: Literal[IndicatorType.forensicartifact] = IndicatorType.forensicartifact

    sources: list[dict] = []
    aliases: list[str] = []
    supported_os: list[str] = []

    def match(self, value: str) -> IndicatorMatch | None:
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
            definition_dict["diamond"] = DiamondModel.victim
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
                    indicator = Regex.find(name=path)
                    if not indicator:
                        try:
                            indicator = Regex(
                                name=path,
                                pattern=pattern,
                                location="filesystem",
                                diamond=DiamondModel.victim,
                                relevant_tags=self.relevant_tags,
                            ).save()
                            indicators.append(indicator)
                        except Exception as error:
                            logging.error(
                                f"Failed to create indicator for {path} (was: {source['attributes']['paths']}): {error}"
                            )
                            continue

                    else:
                        indicator.relevant_tags = list(
                            set(indicator.relevant_tags + self.relevant_tags)
                        )
                        indicator.save()
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

                indicator = Regex.find(name=key)

                if not indicator:
                    try:
                        indicator = Regex(
                            name=key,
                            pattern=pattern,
                            location="registry",
                            diamond=DiamondModel.victim,
                            relevant_tags=self.relevant_tags,
                        ).save()
                        indicators.append(indicator)
                    except Exception as error:
                        logging.error(
                            f"Failed to create indicator for {key} (was: {source['attributes']['keys']}): {error}"
                        )
                        continue
                else:
                    indicator.relevant_tags = list(
                        set(indicator.relevant_tags + self.relevant_tags)
                    )
                    indicator.save()
        if create_links:
            for indicator in indicators:
                indicator.link_to(self, "indicates", f"Indicates {indicator.name}")
        return indicators


ARTIFACT_INTERPOLATION_RE = re.compile(r"%%[a-z._]+%%")
ARTIFACT_INTERPOLATION_RE_HKEY_USERS = re.compile(r"HKEY_USERS\\%%users.sid%%")

TYPE_MAPPING = {
    "regex": Regex,
    "yara": Yara,
    "sigma": Sigma,
    "query": Query,
    "forensicartifact": ForensicArtifact,
    "indicator": Indicator,
    "indicators": Indicator,
}

IndicatorTypes = Annotated[
    Union[Regex, Yara, Sigma, Query, ForensicArtifact], Field(discriminator="type")
]
IndicatorClasses = (
    Type[Regex] | Type[Yara] | Type[Sigma] | Type[Query] | Type[ForensicArtifact]
)
