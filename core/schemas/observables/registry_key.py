from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

"""
Registry Key observable schema class.
key: str - The registry key name.
value: str - The registry key value.
hive: str | None - The registry hive like SYSEM, SOFTWARE, etc.
path_file: str | None - The path to the file that contains the registry key value.
"""


class RegistryKey(Observable):
    type: Literal["regkey"] = ObservableType.registry_key
    key: str
    value: str
    hive: str | None = None
    path_file: str | None = None
