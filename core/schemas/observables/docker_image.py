from typing import Literal

from core.schemas import observable


class DockerImage(observable.Observable):
    type: Literal[observable.ObservableType.docker_image] = (
        observable.ObservableType.docker_image
    )


observable.TYPE_MAPPING[observable.ObservableType.docker_image] = DockerImage
