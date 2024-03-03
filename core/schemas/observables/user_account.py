import datetime
from typing import Literal

from pydantic import model_validator

from core.schemas import observable


class UserAccount(observable.Observable):
    """Represents a user account observable based on the Oasis schema.
    https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_azo70vgj1vm2

    account_login and account_type must be provided.
    Value should to be in the form <ACCOUNT_TYPE>:<ACCOUNT_LOGIN>.
    """

    type: Literal[observable.ObservableType.user_account] = (
        observable.ObservableType.user_account
    )
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

    @model_validator(mode="after")
    def check_timestamp_coherence(self) -> "UserAccount":
        if self.account_created and self.account_expires:
            if self.account_created > self.account_expires:
                raise ValueError(
                    "Account created date is after account expiration date."
                )
        return self


observable.TYPE_MAPPING[observable.ObservableType.user_account] = UserAccount
