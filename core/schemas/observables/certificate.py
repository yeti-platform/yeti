from core.schemas.observable import Observable
import datetime
from pydantic import Field
from core.schemas.observable import ObservableType
from core.helpers import now

import hashlib
from typing import Literal

"""
This is the schema for the Certificate observable type. It inherits from the Observable schema and has the following fields:
    type: ObservableType = ObservableType.certificate
    last_seen: datetime.datetime, the last time the observable was seen
    first_seen: datetime.datetime, the first time the observable was seen
    issuer: str | None, the issuer of the certificate
    subject: str | None, the subject of the certificate
    serial_number: str | None, the serial number of the certificate
    after: datetime.datetime | None, the date after which the certificate is valid
    before: datetime.datetime | None, the date before which the certificate is valid
    fingerprint: str | None, the fingerprint of the certificate
"""


class Certificate(Observable):
    type: Literal["certificate"] = ObservableType.certificate
    last_seen: datetime.datetime = Field(default_factory=now)
    first_seen: datetime.datetime = Field(default_factory=now)
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    after: datetime.datetime | None = None
    before: datetime.datetime | None = None
    fingerprint: str | None = None

    @classmethod
    def from_data(cls, data: str):
        hash_256 = hashlib.sha256(data).hexdigest()
        return cls(value=f"CERT:{hash_256}")
