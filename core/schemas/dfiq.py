import datetime
import logging
import os
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Type

import yaml
from pydantic import BaseModel, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas import indicator
from core.schemas.model import YetiModel


def read_from_data_directory(directory: str) -> int:
    dfiq_kb = {}
    total_added = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if not file.endswith(".yaml"):
                continue
            if "spec" in file or "template" in file:
                # Don't process DIFQ specification files
                continue
            logging.debug("Processing %s/%s", root, file)
            with open(os.path.join(root, file), "r") as f:
                try:
                    dfiq_object = DFIQBase.from_yaml(f.read()).save()
                    total_added += 1
                except (ValueError, KeyError) as e:
                    logging.warning("Error processing %s: %s", file, e)
                    continue

            dfiq_kb[dfiq_object.dfiq_id] = dfiq_object

    for dfiq_id, dfiq_object in dfiq_kb.items():
        dfiq_object.update_parents()
        if dfiq_object.type == DFIQType.approach:
            extract_indicators(dfiq_object)

    return total_added


def extract_indicators(approach) -> None:
    for processor in approach.view.processors:
        for analysis in processor.analysis:
            for step in analysis.steps:
                if step.type == "manual":
                    continue

                query = indicator.Query.find(pattern=step.value)
                if not query:
                    query = indicator.Query(
                        name=f"{step.description} ({step.type})",
                        pattern=step.value,
                        relevant_tags=approach.dfiq_tags or [],
                        query_type=step.type,
                        location=step.type,
                        diamond=indicator.DiamondModel.victim,
                    ).save()
                approach.link_to(query, "query", "Uses query")

    for data in approach.view.data:
        if data.type == "ForensicArtifact":
            artifact = indicator.ForensicArtifact.find(name=data.value)
            if not artifact:
                logging.warning(
                    "Missing artifact %s in %s", data.value, approach.dfiq_id
                )
                continue
            approach.link_to(artifact, "artifact", "Uses artifact")
        else:
            logging.warning("Unknown data type %s in %s", data.type, approach.dfiq_id)


class DFIQType(str, Enum):
    scenario = "scenario"
    facet = "facet"
    question = "question"
    approach = "approach"


class DFIQBase(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "dfiq"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["dfiq"] = "dfiq"

    name: str
    dfiq_id: str
    dfiq_version: str
    dfiq_tags: list[str] | None = None
    contributors: list[str] | None = None
    dfiq_yaml: str
    internal: bool = False

    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)

    @computed_field(return_type=Literal["root_type"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict):
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        return cls(**object)

    @classmethod
    def parse_yaml(cls, yaml_string: str) -> dict[str, Any]:
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        if not isinstance(yaml_data, dict):
            raise ValueError(
                f"Invalid DFIQ YAML (unable to parse into object): {yaml_data}"
            )
        if "type" not in yaml_data:
            raise ValueError(
                f"Invalid DIFQ YAML (missing 'type' attribute): {yaml_data}"
            )
        if yaml_data["type"] not in TYPE_MAPPING:
            raise ValueError(f"Invalid type for DFIQ: {yaml_data['type']}")
        if "id" not in yaml_data:
            raise ValueError(f"Invalid DIFQ YAML (missing 'id' attribute): {yaml_data}")

        if not re.match("^\d+\.\d+\.\d+$", str(yaml_data.get("dfiq_version", ""))):
            raise ValueError(f"Invalid DFIQ version: {yaml_data['dfiq_version']}")

        return yaml_data

    @classmethod
    def from_yaml(cls, yaml_string: str) -> "DFIQBase":
        yaml_data = yaml.safe_load(yaml_string)
        return TYPE_MAPPING[yaml_data["type"]].from_yaml(yaml_string)

    def to_yaml(self) -> str:
        dump = self.model_dump(
            exclude={"created", "modified", "id", "root_type", "dfiq_yaml"}
        )
        dump.pop("internal")
        dump["type"] = dump["type"].removeprefix("DFIQType.")
        dump["display_name"] = dump.pop("name")
        dump["tags"] = dump.pop("dfiq_tags")
        dump["id"] = dump.pop("dfiq_id")
        if dump["contributors"] is None:
            dump.pop("contributors")
        return yaml.dump(dump)

    def update_parents(self) -> None:
        intended_parent_ids = None
        if hasattr(self, "parent_ids"):
            intended_parent_ids = self.parent_ids
        elif self.type == DFIQType.approach:
            intended_parent_ids = [self.dfiq_id.split(".")[0]]
        else:
            return

        intended_parents = [
            DFIQBase.find(dfiq_id=parent_id) for parent_id in intended_parent_ids
        ]
        if not all(intended_parents):
            raise ValueError(
                f"Missing parent(s) {intended_parent_ids} for {self.dfiq_id}"
            )

        # remove all links:
        vertices, relationships, total = self.neighbors()
        for edge in relationships:
            for rel in edge:
                if rel.type not in {t.value for t in DFIQType}:
                    continue
                if rel.target != self.extended_id:
                    continue
                if vertices[rel.source].dfiq_id not in intended_parent_ids:
                    rel.delete()

        for parent in intended_parents:
            parent.link_to(self, self.type, f"Uses DFIQ {self.type}")


class DFIQScenario(DFIQBase):
    description: str

    type: Literal[DFIQType.scenario] = DFIQType.scenario

    @classmethod
    def from_yaml(cls: Type["DFIQScenario"], yaml_string: str) -> "DFIQScenario":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "scenario":
            raise ValueError(f"Invalid type for DFIQ scenario: {yaml_data['type']}")
        # use re.match to check that DFIQ Ids for scenarios start with S[0-1]\d+
        if not re.match(r"^S[0-1]\d+$", yaml_data["id"] or ""):
            raise ValueError(
                f"Invalid DFIQ ID for scenario: {yaml_data['id']}. Must be in the format S[0-1]\d+"
            )
        return cls(
            name=yaml_data["display_name"],
            description=yaml_data["description"],
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            dfiq_yaml=yaml_string,
            internal=yaml_data["id"][1] == "0",
        )


class DFIQFacet(DFIQBase):
    description: str | None

    parent_ids: list[str]

    type: Literal[DFIQType.facet] = DFIQType.facet

    @classmethod
    def from_yaml(cls: Type["DFIQFacet"], yaml_string: str) -> "DFIQFacet":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "facet":
            raise ValueError(f"Invalid type for DFIQ facet: {yaml_data['type']}")
        if not re.match(r"^F[0-1]\d+$", yaml_data["id"] or ""):
            raise ValueError(
                f"Invalid DFIQ ID for facet: {yaml_data['id']}. Must be in the format F[0-1]\d+"
            )

        return cls(
            name=yaml_data["display_name"],
            description=yaml_data.get("description"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            parent_ids=yaml_data["parent_ids"],
            dfiq_yaml=yaml_string,
            internal=yaml_data["id"][1] == "0",
        )


class DFIQQuestion(DFIQBase):
    description: str | None
    parent_ids: list[str]

    type: Literal[DFIQType.question] = DFIQType.question

    @classmethod
    def from_yaml(cls: Type["DFIQQuestion"], yaml_string: str) -> "DFIQQuestion":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "question":
            raise ValueError(f"Invalid type for DFIQ question: {yaml_data['type']}")
        if not re.match(r"^Q[0-1]\d+$", yaml_data["id"] or ""):
            raise ValueError(
                f"Invalid DFIQ ID for question: {yaml_data['id']}. Must be in the format Q[0-1]\d+"
            )

        return cls(
            name=yaml_data["display_name"],
            description=yaml_data.get("description"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            parent_ids=yaml_data["parent_ids"],
            dfiq_yaml=yaml_string,
            internal=yaml_data["id"][1] == "0",
        )


class DFIQData(BaseModel):
    type: str
    value: str


class DFIQProcessorOption(BaseModel):
    type: str
    value: str


class DFIQAnalysisStep(BaseModel):
    description: str
    type: str
    value: str


class DFIQAnalysis(BaseModel):
    name: str
    steps: list[DFIQAnalysisStep] = []


class DFIQProcessors(BaseModel):
    name: str
    options: list[DFIQProcessorOption] = []
    analysis: list[DFIQAnalysis] = []


class DFIQApproachDescription(BaseModel):
    summary: str
    details: str
    references: list[str] = []
    references_internal: list[str] | None = None


class DFIQApproachNotes(BaseModel):
    covered: list[str] = []
    not_covered: list[str] = []


class DFIQApproachView(BaseModel):
    data: list[DFIQData] = []
    notes: DFIQApproachNotes
    processors: list[DFIQProcessors] = []


class DFIQApproach(DFIQBase):
    description: DFIQApproachDescription
    view: DFIQApproachView

    type: Literal[DFIQType.approach] = DFIQType.approach

    @classmethod
    def from_yaml(cls: Type["DFIQApproach"], yaml_string: str) -> "DFIQApproach":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "approach":
            raise ValueError(f"Invalid type for DFIQ approach: {yaml_data['type']}")
        if not re.match(r"^Q[0-1]\d+\.\d+$", yaml_data["id"]):
            raise ValueError(
                f"Invalid DFIQ ID for approach: {yaml_data['id']}. Must be in the format Q[0-1]\d+.\d+"
            )
        if not isinstance(yaml_data["description"], dict):
            raise ValueError(
                f"Invalid DFIQ description for approach (has to be an object): {yaml_data['description']}"
            )
        if not isinstance(yaml_data["view"], dict):
            raise ValueError(
                f"Invalid DFIQ view for approach (has to be an object): {yaml_data['view']}"
            )

        internal = bool(re.match(r"^Q[0-1]\d+\.0\d+$", yaml_data["id"]))
        return cls(
            name=yaml_data["display_name"],
            description=DFIQApproachDescription(**yaml_data["description"]),
            view=DFIQApproachView(**yaml_data["view"]),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            dfiq_yaml=yaml_string,
            internal=internal,
        )


TYPE_MAPPING = {
    "scenario": DFIQScenario,
    "facet": DFIQFacet,
    "question": DFIQQuestion,
    "approach": DFIQApproach,
    "dfiq": DFIQBase,
}


DFIQTypes = DFIQScenario | DFIQFacet | DFIQQuestion | DFIQApproach
DFIQClasses = (
    Type[DFIQScenario] | Type[DFIQFacet] | Type[DFIQQuestion] | Type[DFIQApproach]
)
