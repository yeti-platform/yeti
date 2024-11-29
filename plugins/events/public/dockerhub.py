from core import taskmanager
from core.events.message import EventMessage
from core.schemas import task
from core.schemas.observable import Observable
from plugins.analytics.public.dockerhub import (
    DockerHubApi,
    get_image_context,
    make_relationships,
)


class DockerHubImageEvent(task.EventTask):
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
        "acts_on": "new:observable:(docker_image|container_image)",
    }

    def run(self, message: EventMessage) -> None:
        container_image = message.event.yeti_object
        self.logger.info(f"Analysing container image {container_image.value}")
        if not (
            container_image.type == "docker_image"
            or (
                container_image.type == "container_image"
                and container_image.registry == "docker.io"
            )
        ):
            self.logger.info(
                f"Skipping {container_image.type} {container_image.value} not from docker.io"
            )
            return
        self.logger.info(f"Fetching metadata for {container_image.value}")
        metadata = DockerHubApi.image_full_details(container_image.value)
        if not metadata:
            self.logger.info(f"Image metadata for {container_image.value} not found")
            return
        self.logger.info(f"Adding context for {container_image.value}")
        context = get_image_context(metadata)
        container_image.add_context("hub.docker.com", context)
        make_relationships(container_image, metadata)
        return


taskmanager.TaskManager.register_task(DockerHubImageEvent)
