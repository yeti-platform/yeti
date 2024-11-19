from typing import Literal
from urllib.parse import urlparse

import validators
from pydantic import field_validator

from core.schemas import observable


class Url(observable.Observable):
    type: Literal["url"] = "url"

    @field_validator("value", mode="before")
    def refang(cls, v) -> str:
        return observable.refang(v)

    @classmethod
    def validator(cls, value: str) -> bool:
        # Replace underscores with hyphens in the domain
        # https://stackoverflow.com/a/14622263
        o = urlparse(value)
        value = o._replace(netloc=o.netloc.replace("_", "-")).geturl()
        return validators.url(value, strict_query=False) or False
