import datetime
import hashlib

from pydantic import Field

from core.helpers import now
from core.schemas import observable


class Certificate(observable.Observable):
    """This is the schema for the Certificate observable type.

    Attributes:
        last_seen: the last time the certificate was seen.
        first_seen: the first time the certificate was seen.
        issuer: the issuer of the certificate.
        subject: the certificate subject.
        serial_number: the certificate serial.
        after: the date after which the certificate is valid.
        before: the date before which the certificate is valid.
        fingerprint: the certificate fingerprint.
    """

    type: observable.ObservableType = observable.ObservableType.certificate
    last_seen: datetime.datetime = Field(default_factory=now)
    first_seen: datetime.datetime = Field(default_factory=now)
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    after: datetime.datetime | None = None
    before: datetime.datetime | None = None
    fingerprint: str | None = None

    @classmethod
    def from_data(cls, data: bytes):
        hash_256 = hashlib.sha256(data).hexdigest()
        return cls(value=f"CERT:{hash_256}")
