import re

from core.schemas import observable

bic_matcher = re.compile("^[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}?")


class BIC(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.bic

    @staticmethod
    def is_valid(value: str) -> bool:
        return bic_matcher.match(value)
