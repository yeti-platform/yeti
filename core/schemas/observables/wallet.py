from typing import Literal

from core.schemas import observable


class Wallet(observable.Observable):
    type: Literal[observable.ObservableType.wallet] = observable.ObservableType.wallet
    coin: str | None = None
    address: str | None = None

observable.TYPE_MAPPING[observable.ObservableType.wallet] = Wallet
