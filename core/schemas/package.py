import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, computed_field, model_validator
from typing_extensions import Self

from core.schemas import entity, indicator, observable
from core.schemas.observable import ObservableTypes


class YetiPackageRelationship(BaseModel):
    target: str
    link_type: str = "observes"


class YetiPackage(BaseModel):
    """YetiPackage is a generic package that can contain observables, entities, indicators and relationships.

    timestamp: datetime: timestamp of the event. Can be any of https://docs.pydantic.dev/dev/api/standard_library_types/#datetime-types
    source: str: source of the data that will be added. This is used to build context
    tags: Dict[str, List[str]]: tags to be added to the elements. Key is the element name,
    value is a list of tags to associate with. If the key is "global", the tags will be added to all elements.
    observables: List[ObservableTypes]: list of observables to be added. When adding an unknown observable type,
    the type will be automatically reset to "generic" observable type and a tag will be added with the type following
    this format: type:<obs_type>.
    entities: List[EntityTypes]: list of entities to be added
    indicators: List[Indicator]: list of indicators to be added
    relationships: Dict[str, List[YetiPackageRelationship]]: relationships between elements.
    """

    timestamp: datetime = datetime.now()
    source: str = Field(min_length=3)
    tags: Optional[Dict[str, List[str]]] = {}
    observables: Optional[List[observable.ObservableTypes]] = []
    entities: Optional[List[entity.EntityTypes]] = []
    indicators: Optional[List[indicator.IndicatorTypes]] = []
    relationships: Optional[Dict[str, List[YetiPackageRelationship]]] = {}

    _root_type: Literal["package"] = "package"

    @computed_field(return_type=Literal["indicator"])
    @property
    def root_type(self):
        return self._root_type

    def __init__(self, **data: Any):
        super().__init__(**data)
        self._objects: Dict[str, Any] = {}
        for observable_element in self.observables:
            self._objects[observable_element.value] = observable_element
        for entity_element in self.entities:
            self._objects[entity_element.name] = entity_element
        for indicator_element in self.indicators:
            self._objects[indicator_element.name] = indicator_element

    # Use model validator to convert unknown observable types to generic and add type as tag
    @model_validator(mode="before")
    @classmethod
    def handle_generic_observable_types(cls, data: Any) -> Any:
        if (
            isinstance(data, dict)
            and "observables" in data
            and isinstance(data["observables"], list)
        ):
            for observable_element in data["observables"]:
                if "type" in observable_element:
                    observable_type = observable_element["type"]
                    observable_value = observable_element["value"]
                    if observable_type in observable.TYPE_MAPPING:
                        continue
                    observable_element["type"] = "generic"
                    if observable_value not in data["tags"]:
                        data["tags"][observable_value] = []
                    data["tags"][observable_value].append(f"type:{observable_type}")
        return data

    @classmethod
    def from_json(cls: Self, json_package: str) -> Self:
        package = json.loads(json_package)
        instance = cls(
            timestamp=package["timestamp"],
            source=package["source"],
            tags=package.get("tags", []),
        )
        if "observables" in package:
            for observable_element in package["observables"]:
                instance.add_observable(**observable_element)
        if "entities" in package:
            for entity_element in package["entities"]:
                instance.add_entity(**entity_element)
        if "indicators" in package:
            for indicator_element in package["indicators"]:
                instance.add_indicator(**indicator_element)
        if "relationships" in package:
            for source, relationships in package["relationships"].items():
                for relationship in relationships:
                    instance.add_relationship(source, **relationship)
        return instance

    def add_observable(self, value, type, **kwargs) -> Self:
        if value in self._objects:
            raise ValueError(f'"{value}" already exists')
        if type in observable.TYPE_MAPPING:
            cls = observable.TYPE_MAPPING[type]
        else:
            cls = observable.TYPE_MAPPING["generic"]
            if value not in self.tags:
                self.tags[value] = []
            self.tags[value].append(f"type:{type}")

        kwargs["value"] = value
        instance = cls(**kwargs)
        self.observables.append(instance)
        self._objects[value] = instance
        return self

    def add_entity(self, name, type, **kwargs) -> Self:
        if name in self._objects:
            raise ValueError(f'Entity "{name}" already exists')
        if type not in entity.TYPE_MAPPING:
            raise ValueError(f"Invalid entity type {type}")
        cls = entity.TYPE_MAPPING[type]
        kwargs["name"] = name
        instance = cls(**kwargs)
        self.entities.append(instance)
        self._objects[name] = instance
        return self

    def add_indicator(self, name, type, **kwargs) -> Self:
        if name in self._objects:
            raise ValueError(f'Indicator "{name}" already exists')
        if type not in indicator.TYPE_MAPPING:
            raise ValueError(f"Invalid indicator type: {type}")
        cls = indicator.TYPE_MAPPING[type]
        kwargs["name"] = name
        instance = cls(**kwargs)
        self.indicators.append(instance)
        self._objects[name] = instance
        return self

    # relationships validation is done at save time
    def add_relationship(
        self, source: str, target: str, link_type: str = "related-to"
    ) -> Self:
        if source not in self.relationships:
            self.relationships[source] = []
        for relationship in self.relationships[source]:
            if relationship.target == target:
                raise ValueError(
                    f"Relationship between {source} and {target} already exists"
                )
        relationship = YetiPackageRelationship(target=target, link_type=link_type)
        self.relationships[source].append(relationship)
        return self

    def save(self) -> None:
        if not self.observables and not self.entities and not self.indicators:
            raise ValueError("No elements to save")
        # before saving, let's check that relationships are valid
        for source, relationships in self.relationships.items():
            if source not in self._objects:
                raise ValueError(f'Relationship source "{source}" does not exist')
            for relationship in relationships:
                if relationship.target not in self._objects:
                    raise ValueError(
                        f'Relationship target "{relationship.target}" does not exist'
                    )
        for observable_element in self.observables:
            self._save_observable(observable_element)
        for entity_element in self.entities:
            self._save_entity(entity_element)
        for indicator_element in self.indicators:
            self._save_indicator(indicator_element)
        self._save_relationships()

    def _convert_timestamp(self, timestamp: str | int) -> datetime:
        if isinstance(timestamp, int):
            if timestamp > 10000000000:
                return datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
            else:
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        elif isinstance(timestamp, str):
            if "." in timestamp:
                fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
            else:
                fmt = "%Y-%m-%dT%H:%M:%S%z"
            return datetime.strptime(timestamp, fmt)
        else:
            raise ValueError("Invalid timestamp format")

    def _save_entity(self, element: entity.EntityTypes) -> None:
        yeti_entity = entity.Entity.find(name=element.name, type=element.type)
        if not yeti_entity:
            yeti_entity = element.save()
        if hasattr(yeti_entity, "first_seen") and hasattr(yeti_entity, "last_seen"):
            yeti_entity.first_seen = (
                self.timestamp
                if yeti_entity.first_seen > self.timestamp
                else yeti_entity.first_seen
            )
            yeti_entity.last_seen = (
                self.timestamp
                if yeti_entity.last_seen < self.timestamp
                else yeti_entity.last_seen
            )
            yeti_entity = yeti_entity.save()
        tags = list()
        if yeti_entity.name in self.tags:
            tags.extend(self.tags[yeti_entity.name])
        if "global" in self.tags:
            tags.extend(self.tags["global"])
        if tags:
            yeti_entity.tag(set(tags))
        yeti_entity = self._update_entity_context(yeti_entity)
        self._objects[element.name] = yeti_entity.save()

    def _save_indicator(self, element: indicator.IndicatorTypes) -> None:
        yeti_indicator = indicator.Indicator.find(name=element.name, type=element.type)
        if not yeti_indicator:
            yeti_indicator = element.save()
        tags = list()
        if yeti_indicator.name in self.tags:
            tags.extend(self.tags[yeti_indicator.name])
        if "global" in self.tags:
            tags.extend(self.tags["global"])
        if tags:
            yeti_indicator.tag(set(tags))
        self._objects[element.name] = yeti_indicator.save()

    def _save_observable(self, element: observable.ObservableTypes) -> None:
        yeti_observable = observable.Observable.find(
            value=element.value, type=element.type
        )
        if not yeti_observable:
            # support unknown observable type with generic and adds type as tag: type:<obs_type>
            yeti_observable = element.save()
        tags = list()
        if yeti_observable.value in self.tags:
            tags.extend(self.tags[yeti_observable.value])
        if "global" in self.tags:
            tags.extend(self.tags["global"])
        if tags:
            yeti_observable.tag(set(tags))
        yeti_observable = self._update_observable_context(yeti_observable)
        self._objects[element.value] = yeti_observable.save()

    def _save_relationships(self) -> None:
        for source, relationships in self.relationships.items():
            source_object = self._objects[source]
            for relationship in relationships:
                target_object = self._objects[relationship.target]
                source_object.link_to(target_object, relationship.link_type, "")

    def _update_entity_context(self, yeti_entity: entity.Entity) -> entity.Entity:
        found_idx = -1
        updated_context = {
            "source": self.source,
            "total_seen": 1,
        }
        for idx, context in enumerate(list(yeti_entity.context)):
            if context["source"] == self.source:
                found_idx = idx
                break
        if found_idx != -1:
            # Handle previous context which were not structured as above
            current_context = yeti_entity.context[found_idx]
            updated_context["total_seen"] = current_context.get("total_seen", 0) + 1
            yeti_entity.context[found_idx] = updated_context
            return yeti_entity.save()
        else:
            return yeti_entity.add_context(self.source, updated_context)

    def _update_observable_context(
        self, yeti_observable: observable.Observable
    ) -> observable.Observable:
        found_idx = -1
        updated_context = {
            "source": self.source,
            "total_seen": 1,
            "first_seen": self.timestamp,
            "last_seen": self.timestamp,
        }
        for idx, context in enumerate(list(yeti_observable.context)):
            if context["source"] == self.source:
                found_idx = idx
                break
        if found_idx != -1:
            # Handle previous context which were not structured as above
            current_context = yeti_observable.context[found_idx]
            if not current_context.get("first_seen"):
                first_seen = self.timestamp
            else:
                first_seen = self._convert_timestamp(current_context["first_seen"])
            # keep previous first_seen
            if first_seen < self.timestamp:
                updated_context["first_seen"] = first_seen
            if not current_context.get("last_seen"):
                last_seen = self.timestamp
            else:
                last_seen = self._convert_timestamp(current_context["last_seen"])
            if last_seen > self.timestamp:
                updated_context["last_seen"] = last_seen
            updated_context["total_seen"] = current_context.get("total_seen", 0) + 1
            yeti_observable.context[found_idx] = updated_context
            return yeti_observable.save()
        else:
            return yeti_observable.add_context(self.source, updated_context)
