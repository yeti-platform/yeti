from core.schemas import observable


class MacAddress(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.mac_address