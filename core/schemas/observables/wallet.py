from typing import Literal

from core.schemas import observable


class Wallet(observable.Observable):
    """Represents a wallet observable.

    coin and address must be provided.
    Value should be in the form <COIN>:<ADDRESS>.
    """


    type: Literal[observable.ObservableType.wallet] = observable.ObservableType.wallet
    coin: str | None = None
    address: str | None = None

observable.TYPE_MAPPING[observable.ObservableType.wallet] = Wallet
