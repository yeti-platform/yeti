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
    dfiq_tags: list[str] | None
    contributors: list[str] | None

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

    def to_yaml(self):
        dump = self.model_dump(exclude={"created", "modified", "id", "root_type"})
        dump["type"] = dump["type"].removeprefix("DFIQType.")
        dump["display_name"] = dump.pop("name")
        dump["tags"] = dump.pop("dfiq_tags")
        dump["id"] = dump.pop("dfiq_id")
        if dump["contributors"] is None:
            dump.pop("contributors")
        return yaml.dump(dump)


class DFIQScenario(DFIQBase):
    description: str

    type: Literal[DFIQType.scenario] = DFIQType.scenario

    @classmethod
    def from_yaml(cls: Type["DFIQScenario"], yaml_string: str) -> "DFIQScenario":
        try:
            yaml_data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        return cls(
            name=yaml_data["display_name"],
            description=yaml_data["description"],
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
        )


class DFIQFacet(DFIQBase):
    description: str | None

    parent_ids: list[str]

    type: Literal[DFIQType.facet] = DFIQType.facet

    @classmethod
    def from_yaml(cls: Type["DFIQFacet"], yaml_string: str) -> "DFIQFacet":
        yaml_data = yaml.safe_load(yaml_string)
        return cls(
            name=yaml_data["display_name"],
            description=yaml_data.get("description"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            parent_ids=yaml_data["parent_ids"],
        )


class DFIQQuestion(DFIQBase):
    description: str | None
    parent_ids: list[str]

    type: Literal[DFIQType.question] = DFIQType.question

    @classmethod
    def from_yaml(cls: Type["DFIQQuestion"], yaml_string: str) -> "DFIQQuestion":
        yaml_data = yaml.safe_load(yaml_string)
        return cls(
            name=yaml_data["display_name"],
            description=yaml_data.get("description"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            parent_ids=yaml_data["parent_ids"],
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
        yaml_data = yaml.safe_load(yaml_string)
        return cls(
            name=yaml_data["display_name"],
            description=DFIQApproachDescription(**yaml_data["description"]),
            view=DFIQApproachView(**yaml_data["view"]),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
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
