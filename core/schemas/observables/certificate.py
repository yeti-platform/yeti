from core.schemas.observable import Observable
import datetime
from pydantic import Field
from core.schemas.observable import ObservableType

class Certificate(Observable):
    last_seen: datetime.datetime = Field(default_factory=datetime.datetime.now)
    first_seen: datetime.datetime = Field(default_factory=datetime.datetime.now)
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    after: datetime.datetime | None = None
    before: datetime.datetime | None = None
    type: ObservableType = ObservableType.certificate
    fingerprint: str | None = None