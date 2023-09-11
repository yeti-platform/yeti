from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from core.schemas.observables.md5 import MD5
from core.schemas.observables.sha1 import SHA1
from core.schemas.observables.sha256 import SHA256

'''
File schema

value: str - The value of the file observable file:f{sha256}
type: ObservableType - The type of observable
name: str - The name of the file if it is known
size: int - The size of the file in bytes
sha256: str - The sha256 hash of the file
md5: MD5 - The md5 hash of the file
sha1: SHA1 - The sha1 hash of the file
myme_type: str - The mime type of the file
'''

class File(Observable):
    """Represents a file.

    One of sha256, md5, or sha1 should be provided.
    Value should to be in the form FILE:<HASH>.
    """
    value: str
    type: ObservableType = ObservableType.file
    name: str = None
    size: int = None
    sha256: str = None
    md5: str = None
    sha1: str = None
    mime_type: str = None
