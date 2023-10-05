from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal


class Email(Observable):
    value: str
    type: Literal["email"] = ObservableType.email
