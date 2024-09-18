import re
from typing import Literal

from core.schemas import observable

LINUX_PATH_REGEX = re.compile(r"^(\/[^\/\0]+)+$")
WINDOWS_PATH_REGEX = re.compile(
    r"^(?:[a-zA-Z]\:|\\\\[\w\.]+\\[\w.$]+)\\(?:[\w]+\\)*\w([\w.])+"
)


def path_validator(value):
    return LINUX_PATH_REGEX.match(value) or WINDOWS_PATH_REGEX.match(value)


class Path(observable.Observable):
    type: Literal[observable.ObservableType.path] = observable.ObservableType.path

    @staticmethod
    def is_valid(value: str) -> bool:
        return path_validator(value)
