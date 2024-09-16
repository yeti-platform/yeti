import validators

from core.schemas import observable


class Hostname(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.hostname

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.domain(value)