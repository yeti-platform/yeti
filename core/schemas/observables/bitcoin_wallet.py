from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class BitcoinWallet(Observable):
    value: str
    type: Literal['bitcoin-wallet'] = ObservableType.bitcoin_wallet
