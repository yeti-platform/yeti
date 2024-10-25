from typing import Literal

from core.schemas import observable


class ContainerImage(observable.Observable):
    type: Literal["container_image"] = "container_image"
    registry: str = "docker.io"


class DockerImage(ContainerImage):
    type: Literal["docker_image"] = "docker_image"
