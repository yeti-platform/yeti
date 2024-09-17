import re
from typing import Literal

from core.schemas import observable

linux_path_matcher = re.compile(r"^(\/[^\/\0]+)+$")
windows_path_matcher = re.compile(
    r"^(?:[a-zA-Z]\:|\\\\[\w\.]+\\[\w.$]+)\\(?:[\w]+\\)*\w([\w.])+"
)


def path_validator(value):
    return linux_path_matcher.match(value) or windows_path_matcher.match(value)


class Path(observable.Observable):
    type: Literal[observable.ObservableType.path] = observable.ObservableType.path

    @staticmethod
    def is_valid(value: str) -> bool:
        return path_validator(value)
