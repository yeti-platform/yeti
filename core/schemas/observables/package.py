from core.schemas import observable


class Package(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.package
    version: str = None
    regitry_type: str = None
