from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class RegistryKey(Observable):
    type: ObservableType = ObservableType.registry_key
    key: str
    value: str
    hive: str | None = None
    path_file: str | None = None
