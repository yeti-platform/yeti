from typing import Literal

from core.schemas import observable


class File(observable.Observable):
    """Represents a file.

    One of sha256, md5, or sha1 should be provided.
    Value should to be in the form FILE:<HASH>.
    """

    value: str
    type: Literal[observable.ObservableType.file] = observable.ObservableType.file
    name: str | None = None
    size: int | None = None
    sha256: str | None = None
    md5: str | None = None
    sha1: str | None = None
    mime_type: str | None = None


observable.TYPE_MAPPING[observable.ObservableType.file] = File
