from core.schemas.observable import Observable
from core.schemas.observable import ObservableType


class Email(Observable):
    value: str
    type: ObservableType = ObservableType.email
