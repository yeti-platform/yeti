import re
from typing import Literal

from core.schemas import observable

BIC_MATCHER_REGEX = re.compile("^[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}?")


class BIC(observable.Observable):
    type: Literal[observable.ObservableType.bic] = observable.ObservableType.bic

    @staticmethod
    def is_valid(value: str) -> bool:
        return BIC_MATCHER_REGEX.match(value)
