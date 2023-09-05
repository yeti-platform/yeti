from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from core.schemas.observables.md5 import MD5
from core.schemas.observables.sha1 import SHA1
from core.schemas.observables.sha256 import SHA256

class File(Observable):
    value: str
    type: ObservableType = ObservableType.file
    name: str = None
    size: int = None
    sha256: SHA256 = None
    md5: MD5 = None
    sha1: SHA1 = None
    mime_type: str = None
