from typing import Literal

from core.schemas import observable


class BitcoinWallet(observable.Observable):
    type: Literal[observable.ObservableType.bitcoin_wallet] = observable.ObservableType.bitcoin_wallet


observable.TYPE_MAPPING[observable.ObservableType.bitcoin_wallet] = BitcoinWallet
