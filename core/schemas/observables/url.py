from typing import Literal
from urllib.parse import urlparse

import validators
from pydantic import field_validator

from core.schemas import observable


class Url(observable.Observable):
    type: Literal["url"] = "url"

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = observable.refang(value)
        # Replace underscores with hyphens in the domain
        # https://stackoverflow.com/a/14622263
        o = urlparse(value)
        temp_value = o._replace(netloc=o.netloc.replace("_", "-")).geturl()
        if not validators.url(temp_value, strict_query=False):
            raise ValueError("Invalid url")
        return value
