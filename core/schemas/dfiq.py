import datetime
import logging
import re
from enum import Enum
from typing import ClassVar, Literal, Type

from core import database_arango
from core.helpers import now

from core.schemas.model import YetiModel

from pydantic import (BaseModel, Field, PrivateAttr, computed_field,
                      field_validator)


class DFIQType(str, Enum):
    scenario = "scenario"
    facet = "facet"
    question = "question"
    approach = "approach"


class DFIQBase(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "dfiq"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["scenario"] = "dfiq"

    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)


class DFIQScenario(DFIQBase):
    name: str
    description: str = ""
    dfiq_id: str
    dfiq_version: str
    tags: list[str] = []
    contributors: list[str] = []

    type: Literal[DFIQType.scenario] = DFIQType.scenario


class DFIQFacet(DFIQBase):
    name: str
    description: str = ""
    dfiq_id: str
    dfiq_version: str
    tags: list[str] = []
    contributors: list[str] = []

    type: Literal[DFIQType.facet] = DFIQType.facet


class DFIQQuestion(DFIQBase):
    name: str
    description: str = ""
    dfiq_id: str
    dfiq_version: str
    tags: list[str] = []
    contributors: list[str] = []

    type: Literal[DFIQType.question] = DFIQType.question


class DFIQData(BaseModel):
    type: str
    value: str


class DFIQOption(BaseModel):
    type: str
    value: str


class DFIQAnalysisStep(BaseModel):
    description: str
    type: str
    value: str


class DFIQProcessors(BaseModel):
    name: str
    options: list[DFIQOption] = []
    analysis: list[DFIQAnalysisStep] = []


class DFIQAnalysis(BaseModel):
    name: str
    steps: list[DFIQAnalysisStep] = []


class DFIQApproachView(BaseModel):
    data: list[DFIQData] = []
    notes: str = ""
    processors: list[DFIQProcessors] = []

    type: Literal[DFIQType.approach] = DFIQType.approach

class DFIQApproach(DFIQBase):
    name: str
    description: str = ""
    dfiq_id: str
    dfiq_version: str
    tags: list[str] = []
    contributors: list[str] = []
    view: DFIQApproachView

    type: Literal[DFIQType.approach] = DFIQType.approach
