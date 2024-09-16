import validators

from core.schemas import observable


class Url(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.url

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.url(value)
