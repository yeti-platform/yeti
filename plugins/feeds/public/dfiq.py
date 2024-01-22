import logging
import os
import tempfile
from datetime import timedelta
from io import BytesIO
from zipfile import ZipFile

from core import taskmanager
from core.schemas import dfiq, task, indicator

import yaml


def _process_scenario(data):
    return dfiq.DFIQScenario(
        name=data["display_name"],
        description=data["description"] or "",
        dfiq_id=data["id"],
        dfiq_version=data["dfiq_version"],
        dfiq_tags=[tag.lower() for tag in data.get("tags", []) or []],
        contributors=data.get("contributors", []),
    ).save()


def _process_facet(data):
    facet = dfiq.DFIQFacet(
        name=data["display_name"],
        description=data["description"] or "",
        dfiq_id=data["id"],
        dfiq_version=data["dfiq_version"],
        dfiq_tags=[tag.lower() for tag in data.get("tags", []) or []],
        contributors=data.get("contributors", []),
        parent_ids=data.get("parent_ids", []),
    ).save()
    for parent_id in data.get("parent_ids", []):
        parent = dfiq.DFIQBase.find(dfiq_id=parent_id)
        if not parent:
            logging.error("Missing parent %s for %s", parent_id, data["id"])
        if parent:
            parent.link_to(facet, "facet", "Uses DFIQ Facet")


def _process_question(data):
    question = dfiq.DFIQQuestion(
        name=data["display_name"],
        description=data["description"] or "",
        dfiq_id=data["id"],
        dfiq_version=data["dfiq_version"],
        dfiq_tags=[tag.lower() for tag in data.get("tags", []) or []],
        contributors=data.get("contributors", []),
        parent_ids=data.get("parent_ids", []),
    ).save()
    for parent_id in data.get("parent_ids", []):
        parent = dfiq.DFIQBase.find(dfiq_id=parent_id)
        if not parent:
            logging.error("Missing parent %s for %s", parent_id, data["id"])
        if parent:
            parent.link_to(question, "question", "Uses DFIQ question")


def _process_approach(data):
    approach = dfiq.DFIQApproach(
        name=data["display_name"],
        description=dfiq.DFIQApproachDescription(**data["description"]),
        view=dfiq.DFIQApproachView(**data["view"]),
        dfiq_id=data["id"],
        dfiq_version=data["dfiq_version"],
        dfiq_tags=[tag.lower() for tag in data.get("tags", []) or []],
        contributors=data.get("contributors", [])
    ).save()
    parent_id = approach.dfiq_id.split(".")[0]
    parent = dfiq.DFIQBase.find(dfiq_id=parent_id)
    if not parent:
        logging.error("Missing parent %s for %s", parent_id, data["id"])
    if parent:
        parent.link_to(approach, "approach", "Uses DFIQ approach")

    for processor in approach.view.processors:
        for analysis in processor.analysis:
            for step in analysis.steps:
                if step.type in ("opensearch-query", "opensearch-query-variable"):
                    query = indicator.Query.find(pattern=step.value)
                    if not query:
                        query = indicator.Query(
                            name=step.description,
                            pattern=step.value,
                            relevant_tags=approach.dfiq_tags,
                            query_type=indicator.QueryType.opensearch,
                            location=processor.name,
                            diamond=indicator.DiamondModel.victim
                        ).save()
                    approach.link_to(query, "query", "Uses query")
                else:
                    logging.warning("Unknown step type %s in %s", step.type, approach.dfiq_id)



TYPE_FUNCTIONS = {
    "scenarios": _process_scenario,
    "facets": _process_facet,
    "questions": _process_question,
    "approaches": _process_approach,
}


class DFIQFeed(task.FeedTask):
    _defaults = {
        "name": "MitreAttack",
        "frequency": timedelta(hours=1),
        "type": "feed",
        "description": "DFIQ feed",
    }

    def run(self):
        response = self._make_request(
            "https://github.com/google/dfiq/archive/refs/heads/main.zip"
        )
        if not response:
            logging.info("No response: skipping DFIQ update")
            return

        tempdir = tempfile.TemporaryDirectory()
        ZipFile(BytesIO(response.content)).extractall(path=tempdir.name)
        dfiq_datadir = os.path.join(tempdir.name, "dfiq-main", "data")

        object_cache = {}

        for subdir in TYPE_FUNCTIONS:
            logging.info("Processing %s", subdir)
            obj_count = 0
            if not os.path.isdir(os.path.join(dfiq_datadir, subdir)):
                continue
            for file in os.listdir(os.path.join(dfiq_datadir, subdir)):
                if not file.endswith(".yaml"):
                    continue
                with open(os.path.join(dfiq_datadir, subdir, file), "r") as f:
                    yaml_data = yaml.safe_load(f)
                    TYPE_FUNCTIONS[subdir](yaml_data)
                    obj_count += 1

            logging.info("Processed %s %s objects", obj_count, subdir)


taskmanager.TaskManager.register_task(DFIQFeed)
