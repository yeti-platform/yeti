import argparse
import sys
from os import path
from pymispgalaxies import Clusters, Galaxies
from core.entities.actor import Actor
from pyeti import YetiApi
from mongoengine import connect
from core.user import User

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config


class ImportMisp:
    def __init__(self) -> None:
        self.db = connect("yeti", host=yeti_config.mongodb.host)

    def add_ThreatActor(self):
        clusters = Clusters()
        cluster_threat_actors = clusters.get("threat-actor").cluster
        for ta in cluster_threat_actors["values"]:
            name = None
            description = ""
            tags = []
            try:
                if "description" in ta:
                    description = ta["description"]
                name = ta["value"]
                if "meta" in ta:
                    if (
                        "cfr-suspected-state-sponsor" in ta["meta"]
                        and ta["meta"]["cfr-suspected-state-sponsor"]
                    ):
                        country = "Country Supected: {}.\n".format(
                            ta["meta"]["cfr-suspected-state-sponsor"]
                        )
                        description = "{} {}".format(description, country)
                    if (
                        "cfr-target-category" in ta["meta"]
                        and ta["meta"]["cfr-target-category"]
                    ):
                        target = "Target: {}.\n".format(
                            ",".join(ta["meta"]["cfr-target-category"])
                        )
                        description = "{} {}".format(description, target)
                    if (
                        "cfr-suspected-victims" in ta["meta"]
                        and ta["meta"]["cfr-suspected-victims"]
                    ):
                        victims = "Victims: {}\n.".format(
                            ",".join(ta["meta"]["cfr-suspected-victims"])
                        )
                        description = "{} {}".format(description, victims)
                    if "synonyms" in ta["meta"]:
                        for synonym in ta["meta"]["synonyms"]:
                            tags.append(synonym)
                    tags.append(name)
                actor = Actor.get_or_create(name=name)
                actor.description = description
                actor.tags = tags
                actor.save()
            except Exception as e:
                print(f"Error: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="MISP Galaxies")
    parser.add_argument(
        "-t",
        "--type",
        help="Type of galaxies to retrieve",
        choices=["all", "TA", "Malware"],
        default="all",
    )
    return parser.parse_args()


if __name__ == "__main__":
    import_misp = ImportMisp()
    args = parse_args()
    if args.type == "all":
        import_misp.add_ThreatActor()
