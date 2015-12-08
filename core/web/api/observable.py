from core.web.api.crud import CrudApi
from core.observables import Observable

class ObservableApi(CrudApi):
    search_template = 'observables.html'
    api_frontend = 'observableapi'
    objectmanager = Observable
