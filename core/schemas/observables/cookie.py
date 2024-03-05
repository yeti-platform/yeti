import datetime
from typing import Literal, Optional

from core.schemas import observable


class Cookie(observable.Observable):
    type: Literal[observable.ObservableType.cookie] = observable.ObservableType.cookie

    http_only: bool = False
    secure: bool = False
    type_cookie: Literal[
        "Session management",
        "Tracking",
        "Personalization",
        "Security",
        "Exfiltration",
        "Beaconing",
        "Other",
    ] = "Session management"
    expires: Optional[datetime.datetime] = None
    name: Optional[str] = None
    cookie: Optional[str] = None

observable.TYPE_MAPPING[observable.ObservableType.cookie] = Cookie
