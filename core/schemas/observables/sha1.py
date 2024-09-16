import validators

from core.schemas import observable


class SHA1(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.sha1

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.sha1(value)