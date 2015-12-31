from core.web.api.crud import CrudApi, CrudSearchApi
from core.observables import Observable


class ObservableApi(CrudApi):
    objectmanager = Observable


class ObservableSearchApi(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = Observable
