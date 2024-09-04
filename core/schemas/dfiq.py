import datetime
import glob
import logging
import re
import uuid
from enum import Enum
from typing import Annotated, Any, ClassVar, Literal, Type, Union

import yaml
from packaging.version import Version
from pydantic import BaseModel, Field, computed_field

from core import database_arango
from core.config.config import yeti_config
from core.helpers import now
from core.schemas import indicator
from core.schemas.model import YetiModel

LATEST_SUPPORTED_DFIQ_VERSION = "1.1.0"


def long_text_representer(dumper, data):
    if "1. " in data or "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=">")
    else:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def custom_null_representer(dumper, data):
    # Represent 'None' as an empty string
    return dumper.represent_scalar("tag:yaml.org,2002:null", "")


yaml.add_representer(str, long_text_representer)
yaml.add_representer(type(None), custom_null_representer)


def read_from_data_directory(globpath: str, overwrite: bool = False) -> int:
    """Read DFIQ files from a directory and add them to the database.

    Args:
        globpath: Glob path to search for DFIQ files (supports recursion).
        overwrite: Whether to overwrite existing DFIQs with the same ID.
    """
    dfiq_kb = {}
    total_added = 0
    for file in glob.glob(globpath, recursive=True):
        if not file.endswith(".yaml"):
            continue
        logging.debug("Processing %s", file)
        with open(file, "r") as f:
            try:
                dfiq_object = DFIQBase.from_yaml(f.read())
                if not overwrite:
                    db_dfiq = None
                    if dfiq_object.uuid:
                        db_dfiq = DFIQBase.find(uuid=dfiq_object.uuid)
                    if not db_dfiq and dfiq_object.dfiq_id:
                        db_dfiq = DFIQBase.find(dfiq_id=dfiq_object.dfiq_id)
                    if db_dfiq:
                        incoming_v = Version(dfiq_object.dfiq_version)
                        if incoming_v > Version(LATEST_SUPPORTED_DFIQ_VERSION):
                            logging.warning(
                                "DFIQ %s has unsupported version %s, skipping",
                                dfiq_object.dfiq_id,
                                dfiq_object.dfiq_version,
                            )
                            continue
                        db_v = Version(db_dfiq.dfiq_version)
                        if incoming_v <= db_v:
                            logging.info(
                                "DFIQ %s already exists, skipping",
                                dfiq_object.dfiq_id,
                            )
                        continue
                if not dfiq_object.uuid:
                    dfiq_object.uuid = str(uuid.uuid4())
                dfiq_object = dfiq_object.save()
                total_added += 1
            except (ValueError, KeyError) as e:
                logging.warning("Error processing %s: %s", file, e)
                raise e

        dfiq_kb[dfiq_object.dfiq_id] = dfiq_object

    for dfiq_id, dfiq_object in dfiq_kb.items():
        dfiq_object.update_parents(soft_fail=True)
        if dfiq_object.type == DFIQType.question:
            extract_indicators(dfiq_object)

    return total_added


def extract_indicators(question: "DFIQQuestion") -> None:
    for approach in question.approaches:
        for step in approach.steps:
            if step.type == "manual":
                continue

            if step.type in ("ForensicArtifact", "artifact"):
                artifact = indicator.ForensicArtifact.find(name=step.value)
                if not artifact:
                    logging.warning(
                        "Missing artifact %s in %s", step.value, question.dfiq_id
                    )
                    continue
                question.link_to(artifact, "artifact", "Uses artifact")
                continue

            elif step.type and step.value and "query" in step.type:
                query = indicator.Query.find(pattern=step.value)
                if not query:
                    query = indicator.Query(
                        name=f"{step.name} ({step.type})",
                        description=step.description or "",
                        pattern=step.value,
                        relevant_tags=[t.lower() for t in approach.tags] or [],
                        query_type=step.type,
                        location=step.type,
                        diamond=indicator.DiamondModel.victim,
                    ).save()
                question.link_to(query, "query", "Uses query")

            else:
                logging.warning(
                    "Unknown step type %s in %s", step.type, question.dfiq_id
                )


class DFIQType(str, Enum):
    scenario = "scenario"
    facet = "facet"
    question = "question"


class DFIQBase(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "dfiq"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["dfiq"] = "dfiq"

    name: str = Field(min_length=1)
    uuid: str | None = None
    dfiq_id: str | None = None
    dfiq_version: str = Field(min_length=1)
    dfiq_tags: list[str] | None = None
    contributors: list[str] | None = None
    dfiq_yaml: str = Field(min_length=1)

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

        if not re.match(r"^\d+\.\d+\.\d+$", str(yaml_data.get("dfiq_version", ""))):
            raise ValueError(f"Invalid DFIQ version: {yaml_data['dfiq_version']}")

        return yaml_data

    @classmethod
    def from_yaml(cls, yaml_string: str) -> "DFIQBase":
        yaml_data = yaml.safe_load(yaml_string)
        return TYPE_MAPPING[yaml_data["type"]].from_yaml(yaml_string)

    def to_yaml(self, sort_keys=False) -> str:
        dump = self.model_dump(
            exclude={"created", "modified", "id", "root_type", "dfiq_yaml"}
        )
        dump["type"] = dump["type"].removeprefix("DFIQType.")
        dump["name"] = dump.pop("name")
        dump["id"] = dump.pop("dfiq_id")
        dump["uuid"] = dump.pop("uuid")
        dump["description"] = dump.pop("description")
        dump["tags"] = dump.pop("dfiq_tags")
        if dump["contributors"] is None:
            dump.pop("contributors")
        return yaml.dump(
            dump,
            default_flow_style=False,
            sort_keys=sort_keys,
            explicit_start=True,
            indent=2,
        )

    def update_parents(self, soft_fail=False) -> None:
        intended_parent_ids = None
        if getattr(self, "parent_ids", []):
            intended_parent_ids = self.parent_ids
        else:
            return

        intended_parents = []
        for parent_id in intended_parent_ids:
            parent = DFIQBase.find(dfiq_id=parent_id)
            if not parent:
                parent = DFIQBase.find(uuid=parent_id)
            intended_parents.append(parent)

        if not all(intended_parents):
            actual_parents = {
                intended_parent.dfiq_id
                for intended_parent in intended_parents
                if intended_parent
            }
            missing_parents = set(intended_parent_ids) - actual_parents
            if soft_fail:
                logging.warning(
                    "Missing parent(s) %s for %s", missing_parents, self.dfiq_id
                )
                return
            raise ValueError(f"Missing parent(s) {missing_parents} for {self.dfiq_id}")

        # remove all links:
        vertices, relationships, total = self.neighbors()
        for edge in relationships:
            for rel in edge:
                if rel.type not in {t.value for t in DFIQType}:
                    continue
                if rel.target != self.extended_id:
                    continue
                if (
                    vertices[rel.source].dfiq_id and vertices[rel.source].uuid
                ) not in intended_parent_ids:
                    rel.delete()

        for parent in intended_parents:
            parent.link_to(self, self.type, f"Uses DFIQ {self.type}")


class DFIQScenario(DFIQBase):
    _type_filter: ClassVar[str] = DFIQType.scenario

    description: str
    type: Literal[DFIQType.scenario] = DFIQType.scenario

    @classmethod
    def from_yaml(cls: Type["DFIQScenario"], yaml_string: str) -> "DFIQScenario":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "scenario":
            raise ValueError(f"Invalid type for DFIQ scenario: {yaml_data['type']}")
        # use re.match to check that DFIQ Ids for scenarios start with S[0-1]\d+
        if yaml_data.get("id") and not re.match(r"^S[0-1]\d+$", yaml_data["id"] or ""):
            raise ValueError(
                f"Invalid DFIQ ID for scenario: {yaml_data['id']}. Must be in the format S[0-1]\d+"
            )
        return cls(
            name=yaml_data["name"],
            description=yaml_data["description"],
            uuid=yaml_data.get("uuid"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            dfiq_yaml=yaml_string,
        )


class DFIQFacet(DFIQBase):
    _type_filter: ClassVar[str] = DFIQType.facet

    description: str | None
    parent_ids: list[str]
    type: Literal[DFIQType.facet] = DFIQType.facet

    @classmethod
    def from_yaml(cls: Type["DFIQFacet"], yaml_string: str) -> "DFIQFacet":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "facet":
            raise ValueError(f"Invalid type for DFIQ facet: {yaml_data['type']}")
        if yaml_data.get("id") and not re.match(r"^F[0-1]\d+$", yaml_data["id"] or ""):
            raise ValueError(
                f"Invalid DFIQ ID for facet: {yaml_data['id']}. Must be in the format F[0-1]\d+"
            )

        return cls(
            name=yaml_data["name"],
            description=yaml_data.get("description"),
            uuid=yaml_data.get("uuid"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            parent_ids=yaml_data["parent_ids"],
            dfiq_yaml=yaml_string,
        )


class DFIQQuestion(DFIQBase):
    _type_filter: ClassVar[str] = DFIQType.question

    description: str | None
    parent_ids: list[str]
    type: Literal[DFIQType.question] = DFIQType.question
    approaches: list["DFIQApproach"] = []

    @classmethod
    def from_yaml(cls: Type["DFIQQuestion"], yaml_string: str) -> "DFIQQuestion":
        yaml_data = cls.parse_yaml(yaml_string)
        if yaml_data["type"] != "question":
            raise ValueError(f"Invalid type for DFIQ question: {yaml_data['type']}")
        if yaml_data.get("id") and not re.match(r"^Q[0-1]\d+$", yaml_data["id"] or ""):
            raise ValueError(
                f"Invalid DFIQ ID for question: {yaml_data['id']}. Must be in the format Q[0-1]\d+"
            )

        return cls(
            name=yaml_data["name"],
            description=yaml_data.get("description"),
            uuid=yaml_data.get("uuid"),
            dfiq_id=yaml_data["id"],
            dfiq_version=yaml_data["dfiq_version"],
            dfiq_tags=yaml_data.get("tags"),
            contributors=yaml_data.get("contributors"),
            parent_ids=yaml_data["parent_ids"],
            dfiq_yaml=yaml_string,
            approaches=yaml_data.get("approaches", []),
        )


class DFIQApproachStep(BaseModel):
    name: str = Field(min_length=1)
    description: str | None = None
    stage: str = Field(min_length=1)
    type: str | None = None
    value: str | None = None


class DFIQApproachNotes(BaseModel):
    covered: list[str] = []
    not_covered: list[str] = []


class DFIQApproach(BaseModel):
    name: str = Field(min_length=1)
    description: str
    tags: list[str] = []
    references: list[str] = []
    notes: DFIQApproachNotes | None = None
    steps: list[DFIQApproachStep] = []


TYPE_MAPPING = {
    "scenario": DFIQScenario,
    "facet": DFIQFacet,
    "question": DFIQQuestion,
    "dfiq": DFIQBase,
}


DFIQTypes = Annotated[
    Union[DFIQScenario, DFIQFacet, DFIQQuestion],
    Field(discriminator="type"),
]
DFIQClasses = Type[DFIQScenario] | Type[DFIQFacet] | Type[DFIQQuestion]
