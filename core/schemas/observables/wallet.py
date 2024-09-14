from core.schemas import observable


class Wallet(observable.Observable):
    """Represents a wallet observable.

    coin and address must be provided.
    Value should be in the form <COIN>:<ADDRESS>.
    """

    type: observable.ObservableType = observable.ObservableType.wallet
    coin: str | None = None
    address: str | None = None
