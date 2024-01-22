import datetime
from enum import Enum
from typing import ClassVar, Literal, Type

from core import database_arango
from core.helpers import now

from core.schemas.model import YetiModel

from pydantic import BaseModel, Field, computed_field


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
    description: str = ""
    dfiq_id: str
    dfiq_version: str
    dfiq_tags: list[str] = []
    contributors: list[str] = []

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


class DFIQScenario(DFIQBase):
    parent_ids: list[str] = []

    type: Literal[DFIQType.scenario] = DFIQType.scenario


class DFIQFacet(DFIQBase):
    parent_ids: list[str] = []

    type: Literal[DFIQType.facet] = DFIQType.facet


class DFIQQuestion(DFIQBase):
    parent_ids: list[str] = []

    type: Literal[DFIQType.question] = DFIQType.question


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
    references_internal: list[str] = []


class DFIQApproachNotes(BaseModel):
    covered: list[str] = []
    not_covered: list[str] = []


class DFIQApproachView(BaseModel):
    data: list[DFIQData] = []
    notes: DFIQApproachNotes
    processors: list[DFIQProcessors] = []

    type: Literal[DFIQType.approach] = DFIQType.approach


class DFIQApproach(DFIQBase):
    description: DFIQApproachDescription
    view: DFIQApproachView

    type: Literal[DFIQType.approach] = DFIQType.approach


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
