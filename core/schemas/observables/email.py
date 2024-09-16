import validators

from core.schemas import observable


class Email(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.email

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.email(value)