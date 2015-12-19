from core.web.api.crud import CrudApi
from core.observables import Observable


class ObservableApi(CrudApi):

    template = 'observable_api.html'
    objectmanager = Observable
