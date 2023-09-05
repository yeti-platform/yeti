from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class BitcoinWallet(Observable):
    value: str
    type: ObservableType = ObservableType.bitcoin_wallet