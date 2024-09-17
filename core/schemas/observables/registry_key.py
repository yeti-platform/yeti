from enum import Enum
from typing import Literal

from core.schemas import observable


class RegistryHive(str, Enum):
    """Registry Hive enum class."""

    HKEY_CURRENT_CONFIG = "HKEY_CURRENT_CONFIG"
    HKEY_CURRENT_USER = "HKEY_CURRENT_USER"
    HKEY_LOCAL_MACHINE_SAM = "HKEY_LOCAL_MACHINE_SAM"
    HKEY_LOCAL_MACHINE_Security = "HKEY_LOCAL_MACHINE_Security"
    HKEY_LOCAL_MACHINE_Software = "HKEY_LOCAL_MACHINE_Software"
    HKEY_LOCAL_MACHINE_System = "HKEY_LOCAL_MACHINE_System"
    HKEY_USERS_DEFAULT = "HKEY_USERS_DEFAULT"


class RegistryKey(observable.Observable):
    """Registry Key observable schema class.

    Attributes:
        key: The registry key name.
        value: The registry key value.
        hive: The registry hive like SYSEM, SOFTWARE, etc.
        path_file: The filesystem path to the file that contains the registry key value.
    """

    type: Literal[
        observable.ObservableType.registry_key
    ] = observable.ObservableType.registry_key
    key: str
    data: bytes
    hive: RegistryHive
    path_file: str | None = None
