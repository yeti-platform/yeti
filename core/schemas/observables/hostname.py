from typing import Literal

import validators
from pydantic import field_validator

from core.schemas import observable


class Hostname(observable.Observable):
    type: Literal["hostname"] = "hostname"

    @field_validator("value", mode="before")
    def refang(cls, v) -> str:
        return observable.refang(v)

    @classmethod
    def validator(cls, value: str) -> bool:
        # Replace underscores with hyphens in the domain
        # https://stackoverflow.com/a/14622263
        value = value.replace("_", "-")
        return validators.domain(value) or False
