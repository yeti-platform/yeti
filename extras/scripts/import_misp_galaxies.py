import argparse
import sys
from os import path
from pymispgalaxies import Clusters, Galaxies
from core.entities.actor import Actor
from pyeti import YetiApi
from mongoengine import connect
from core.entities.malware import Malware
from core.user import User

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config


class ImportMisp:
    def __init__(self) -> None:
        self.db = connect("yeti", host=yeti_config.mongodb.host)
        self.clusters = Clusters()

    def add_ThreatActor(self):

        cluster_threat_actors = self.clusters.get("threat-actor")
        for name_ta, obj_dict in cluster_threat_actors.cluster_values.items():
            name = None
            description = ""
            tags = []
            ta = obj_dict.to_dict()
            try:
                if "description" in ta:
                    description = ta["description"]
                name = ta["value"]
                if "meta" in ta:
                    meta = ta["meta"].to_dict()
                    if (
                        "cfr-suspected-state-sponsor" in meta
                        and meta["cfr-suspected-state-sponsor"]
                    ):
                        country = "Country Supected: {}.\n".format(
                            meta["cfr-suspected-state-sponsor"]
                        )
                        description = "{} {}".format(description, country)
                    if "cfr-target-category" in meta and meta["cfr-target-category"]:
                        target = "Target: {}.\n".format(
                            ",".join(meta["cfr-target-category"])
                        )
                        description = "{} {}".format(description, target)
                    if (
                        "cfr-suspected-victims" in meta
                        and meta["cfr-suspected-victims"]
                    ):
                        victims = "Victims: {}\n.".format(
                            ",".join(meta["cfr-suspected-victims"])
                        )
                        description = "{} {}".format(description, victims)
                    if "synonyms" in meta:
                        for synonym in meta["synonyms"]:
                            tags.append(synonym)
                    tags.append(name)
                actor = Actor.get_or_create(name=name)
                actor.description = description
                actor.tags = tags
                actor.save()
            except Exception as e:
                print(f"Error: {e}")

    def add_Malware(self, name_cluster="malpedia"):
        cluster_malware = self.clusters.get(name_cluster)
        for name, obj_dict in cluster_malware.cluster_values.items():
            malware = obj_dict.to_dict()
            name = None
            description = ""
            tags = []
            try:
                if "description" in malware:
                    description = malware["description"]
                name = malware["value"]
                if "meta" in malware:
                    meta = malware["meta"].to_dict()
                    if "synonyms" in meta:
                        for synonym in meta["synonyms"]:
                            tags.append(synonym)
                    tags.append(name)
                malware_new = Malware.get_or_create(name=name)
                malware_new.description = description
                malware_new.tags = tags
                malware_new.save()
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
        import_misp.add_Malware()
