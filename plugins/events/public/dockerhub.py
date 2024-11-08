from core import taskmanager
from core.events.message import EventMessage
from core.schemas import task
from core.schemas.observable import Observable
from plugins.analytics.public.dockerhub import DockerHubApi, DockerHubObservables


class DockerHubImageEvent(task.EventTask, DockerHubObservables):
    """DockerHubImageEvent is triggered for (new|update):observable:(docker_image|container_image).
    It queries docker hub to get more details related to docker_image / container_image observable.

    This task adds several information as context to docker_image / container_image:
    * Image stats: provide details about pulls, registered, updated
    * Image details: provide information related to image tags including layers information and instructions
    * User details: provides details about the user owning the image.

    This analytics also creates new observables:
    * generic observable with tag type:user_account to link to a user
    * sha256 including image's digest, layers' digests and added files' digests
    """

    _defaults = {
        "name": "DockerImageAnalyticsOnEvent",
        "description": "Fetch metadata from docker hub for a docker image",
        "acts_on": "(new|update):observable:(docker_image|container_image)",
    }

    def run(self, message: EventMessage) -> None:
        container_image: Observable = message.event.yeti_object
        self.logger.info(f"Analysing container image {container_image.value}")
        if container_image.type != "docker_image" or (
            container_image.type == "container_image"
            and container_image.registry != "docker.io"
        ):
            return
        metadata = DockerHubApi.image_full_details(container_image.value)
        if not metadata:
            return
        context = self._get_image_context(metadata)
        container_image.add_context("hub.docker.com", context)
        self._make_relationships(container_image, metadata)
        return


taskmanager.TaskManager.register_task(DockerHubImageEvent)
