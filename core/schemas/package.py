import json
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, model_validator
from typing_extensions import Self

from core.schemas import entity, indicator, observable


class YetiPackageElement(BaseModel):
    model_config = ConfigDict(extra='allow')
    type: str
    context: Optional[Dict[str, Any]] = {}
    link_to: Optional[List[str]] = []
    link_type: Optional[str] = "observes"


class YetiPackage(BaseModel):
    timestamp: str | int  # add validator
    source: str
    tags: Optional[List[str]] = []
    observables: Optional[Dict[str, YetiPackageElement]] = {}
    entities: Optional[Dict[str, YetiPackageElement]] = {}
    indicators: Optional[Dict[str, YetiPackageElement]] = {}
    
    _exclude_from_model_dump: ClassVar[List[str]] = ["type", "context", "link_to", "link_type"]
    _yeti_objects: ClassVar[Dict[str, observable.Observable | entity.Entity | indicator.Indicator]] = {}
    _relationship_types = ClassVar[Dict[str, str]]

    def __init__(self, **data: Any):
        super().__init__(**data)
        self._timestamp_dt: datetime = self._convert_timestamp(self.timestamp)


    @classmethod
    def from_json(cls: Self, json_input: str) -> Self:
        return cls(**json.loads(json_input))

    # We only need to validate relationships.
    @model_validator(mode="after")
    def validate_elements(self) -> Self:
        self._relationship_types = {}
        # Should we thinkg about key collision between entities, observables and indicators?
        element_keys = set(self.observables) | set(self.entities) | set(self.indicators)
        for element_type in ["observables", "entities", "indicators"]:
            for element_key, element in getattr(self, element_type).items():
                model = element.model_dump(exclude=self._exclude_from_model_dump)
                if element_type == "entities":
                    model["name"] = element_key
                    cls = entity.TYPE_MAPPING[element.type]
                elif element_type == "indicators":
                    model["name"] = element_key
                    cls = indicator.TYPE_MAPPING[element.type]
                else:
                    model["value"] = element_key
                    cls = observable.TYPE_MAPPING[element.type]
                cls(**model)
                # validate relationships
                for targeted_element in element.link_to:
                    if targeted_element not in element_keys:
                        error = f"Relationship with <{targeted_element}> defined for {element_type} {element_key} does not exist"
                        raise ValueError(error)
                self._relationship_types[element_key] = element.link_type
        return self

    def save(self) -> None:
        if self.observables:
            for observable_key, observable_element in self.observables.items():
                print("Saving observable ", observable_key)
                self._save_observable(observable_key, observable_element)
        if self.entities:
            for entity_key, entity_element in self.entities.items():
                #print("Saving entity ", entity_key)
                self._save_entity(entity_key, entity_element)
        if self.indicators:
            for indicator_key, indicator_element in self.indicators.items():
                self._save_indicator(indicator_key, indicator_element)
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

    def _save_entity(self, name: str, element: YetiPackageElement) -> None:
        # Create or get honeypot
        yeti_entity = entity.Entity.find(name=name, type=element.type)
        if not yeti_entity:
            model = element.model_dump(exclude=self._exclude_from_model_dump)
            model["name"] = name
            cls = entity.TYPE_MAPPING[element.type]
            if "first_seen" not in model:
                model["first_seen"] = self.timestamp
            if "last_seen" not in model:
                model["last_seen"] = self.timestamp
            yeti_entity = cls(**model).save()
        else:
            yeti_entity.first_seen = (
                self._timestamp_dt
                if yeti_entity.first_seen > self._timestamp_dt
                else yeti_entity.first_seen
            )
            yeti_entity.last_seen = (
                self._timestamp_dt
                if yeti_entity.last_seen < self._timestamp_dt
                else yeti_entity.last_seen
            )
            yeti_entity = yeti_entity.save()
        if self.tags:
            yeti_entity.tag(self.tags)
        yeti_entity = yeti_entity.save()
        self._yeti_objects[name] = self._update_entity_context(yeti_entity)


    def _save_indicator(self, name: str, element: YetiPackageElement) -> None:
        yeti_indicator = indicator.Indicator.find(name=name, type=element.type)
        if not yeti_indicator:
            model = element.model_dump(exclude=self._exclude_from_model_dump)
            model["name"] = name
            cls = indicator.TYPE_MAPPING[element.type]
            yeti_indicator = cls(**model).save()
        if self.tags:
            yeti_indicator.tag(self.tags)
        self._yeti_objects[name] = yeti_indicator.save()


    def _save_observable(self, value: str, element: YetiPackageElement) -> None:
        yeti_observable = observable.Observable.find(value=value, type=element.type)
        tags = self.tags
        if not yeti_observable:
            # support unknown observable type with generic and adds type as tag: type:<obs_type>
            if element.type not in observable.TYPE_MAPPING:
                cls = observable.Generic
                tags.append(f"type:{element.type}")
            else:
                cls = observable.TYPE_MAPPING[element.type]
            model = element.model_dump(exclude=self._exclude_from_model_dump)
            model["value"] = value
            yeti_observable = cls(**model).save()
        if tags:
            yeti_observable.tag(tags)
        yeti_observable = yeti_observable.save()
        self._yeti_objects[value] = self._update_observable_context(yeti_observable)

    def _save_relationships(self) -> None:
        for element_type in ["observables", "entities", "indicators"]:
            for element_key, element in getattr(self, element_type).items():
                if not element.link_to:
                    continue
                for targeted_element in element.link_to:
                    source = self._yeti_objects[element_key]
                    target = self._yeti_objects[targeted_element]
                    link_type = self._relationship_types[targeted_element]
                    source.link_to(target, link_type, "")

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

    def _update_observable_context(self, yeti_observable: observable.Observable) -> observable.Observable:
        found_idx = -1
        updated_context = {
            "source": self.source,
            "total_seen": 1,
            "first_seen": self._timestamp_dt,
            "last_seen": self._timestamp_dt,
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
            if first_seen < self._timestamp_dt:
                updated_context["first_seen"] = first_seen
            if not current_context.get("last_seen"):
                last_seen = self.timestamp
            else:
                last_seen = self._convert_timestamp(current_context["last_seen"])
            if last_seen > self._timestamp_dt:
                updated_context["last_seen"] = last_seen
            updated_context["total_seen"] = current_context.get("total_seen", 0) + 1
            yeti_observable.context[found_idx] = updated_context
            return yeti_observable.save()
        else:
            return yeti_observable.add_context(self.source, updated_context)
