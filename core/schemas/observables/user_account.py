import datetime
from typing import Literal

from core.schemas import observable


class UserAccount(observable.Observable):
    type: Literal[observable.ObservableType.user_account] = observable.ObservableType.user_account
    user_id: str | None = None
    credential: str | None = None
    account_login: str | None = None
    account_type: str | None = None
    display_name: str | None = None
    is_service_account: bool | None = None
    is_privileged: bool | None = None
    can_escalate_privs: bool | None = None
    is_disabled: bool | None = None
    account_created: datetime.datetime | None = None
    account_expires: datetime.datetime | None = None
    credential_last_changed: datetime.datetime | None = None
    account_first_login: datetime.datetime | None = None
    account_last_login: datetime.datetime | None = None


observable.TYPE_MAPPING[observable.ObservableType.user_account] = UserAccount