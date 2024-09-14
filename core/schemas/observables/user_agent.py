from core.schemas import observable


class UserAgent(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.user_agent