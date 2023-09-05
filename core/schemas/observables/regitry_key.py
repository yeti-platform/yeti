from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class RegistryKey(Observable):
    value: str
    type: ObservableType = ObservableType.registry_key
    hive: str | None = None
    path_file: str | None = None