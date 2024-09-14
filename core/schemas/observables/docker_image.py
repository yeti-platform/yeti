from core.schemas import observable


class DockerImage(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.docker_image
