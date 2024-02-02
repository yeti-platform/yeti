import logging
from datetime import datetime, timedelta

from timesketch_api_client import client

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import observable, task
from core.schemas.entity import Investigation
from core.schemas.observables import hostname, ipv4, md5, path, sha1, sha256, url

TIMESKETCH_TYPE_MAPPING = {
    "ipv4": ipv4.IPv4,
    "hostname": hostname.Hostname,
    "hash_sha1": sha1.SHA1,
    "hash_md5": md5.MD5,
    "hash_sha256": sha256.SHA256,
    "url": url.Url,
    "fs_path": path.Path,
}


class Timesketch(task.FeedTask):
    _defaults = {
        "name": "Timesketch",
        "frequency": timedelta(hours=1),
        "type": "feed",
        "description": "This feed creates Investigations from a Timesketch server.",
    }

    def run(self):
        endpoint = yeti_config.get("timesketch", "endpoint")
        username = yeti_config.get("timesketch", "username")
        password = yeti_config.get("timesketch", "password")

        if not endpoint:
            msg = "Timesketch cannot proceed without an endpoint."
            logging.error(msg)
            raise RuntimeError(msg)

        ts_client = client.TimesketchApi(endpoint, username, password)

        sketches = ts_client.list_sketches()

        for sketch in sketches:
            description = "# Timelines\n\n"
            for timeline in sketch.list_timelines():
                description += f"- {timeline.name}\n"

            created_at = datetime.strptime(
                sketch.resource_data["objects"][0]["created_at"], "%Y-%m-%dT%H:%M:%S.%f"
            )

            investigation = Investigation(
                name=sketch.name,
                created=created_at,
                reference=f"{endpoint}/sketch/{sketch.id}",
                description=description,
            ).save()
            for intel in sketch.get_intelligence_attribute():
                observable_type = TIMESKETCH_TYPE_MAPPING.get(intel["type"])
                if observable_type:
                    obs = observable_type(value=intel["ioc"]).save()
                else:
                    try:
                        obs = observable.Observable.add_text(intel["ioc"])
                    except ValueError as error:
                        logging.error(
                            "Error adding observable %s from Timesketch: %s",
                            intel["ioc"],
                            error,
                        )
                        continue

                obs.tag(intel["tags"])
                obs.add_context(
                    "timesketch",
                    {
                        "link": f"{endpoint}/sketch/{sketch.id}",
                        "id": sketch.id,
                        "timesketch_tags": intel["tags"],
                    },
                )
                obs.link_to(
                    investigation, "seen in", f"Observable seen in {investigation.name}"
                )


taskmanager.TaskManager.register_task(Timesketch)
