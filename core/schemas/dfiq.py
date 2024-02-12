import datetime
from enum import Enum
from typing import ClassVar, Literal, Type

import yaml
from pydantic import BaseModel, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiModel


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
    def from_yaml(cls, yaml_string: str) -> "DFIQBase":
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        if yaml_data["type"] not in TYPE_MAPPING:
            raise ValueError(f"Invalid type for DFIQ: {yaml_data['type']}")
        return TYPE_MAPPING[yaml_data["type"]].from_yaml(yaml_string)

    def to_yaml(self) -> str:
        dump = self.model_dump(
            exclude={"created", "modified", "id", "root_type", "dfiq_yaml"}
        )
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
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        if yaml_data["type"] != "scenario":
            raise ValueError(f"Invalid type for DFIQ scenario: {yaml_data['type']}")

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
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        if yaml_data["type"] != "facet":
            raise ValueError(f"Invalid type for DFIQ facet: {yaml_data['type']}")

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
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        if yaml_data["type"] != "question":
            raise ValueError(f"Invalid type for DFIQ question: {yaml_data['type']}")

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
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        if yaml_data["type"] != "approach":
            raise ValueError(f"Invalid type for DFIQ approach: {yaml_data['type']}")
        return cls(
            name=yaml_data["display_name"],
            description=DFIQApproachDescription(**yaml_data["description"]),
            view=DFIQApproachView(**yaml_data["view"]),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            dfiq_yaml=yaml_string,
            internal=yaml_data["id"][1] == "0",
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
