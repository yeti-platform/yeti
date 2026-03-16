import logging
from datetime import timedelta
import json

import httpx

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import observable, task
from core.schemas.entities import investigation

AGENT_HTTP_BASE = yeti_config.get("agents", "http_root")
AGENT_STREAM_ENDPOINT = f"{AGENT_HTTP_BASE}/run_stream?agent_name=ioc_analyzer"

FILTER_TAG = "extract_investigation"


class UrlExtractInvestigation(task.AnalyticsTask):
    _defaults = {
        "name": "UrlExtractInvestigation",
        "description": f"Extracts investigation details (summaries, IOCs, etc.) from URLs tagged with '{FILTER_TAG}' using LLMs",
        "frequency": timedelta(hours=1),
    }

    def run(self):
        urls, _ = observable.Observable.filter(
            query_args={"tags.name": FILTER_TAG, "type": "url"}
        )

        with httpx.Client(timeout=120.0) as client:
            for url_obs in urls:
                self.process_url(client, AGENT_STREAM_ENDPOINT, url_obs)

    def process_url(
        self, client: httpx.Client, endpoint: str, url_obs: observable.Observable
    ):
        payload = {
            "user_id": "analytics_task",
            "session_id": f"extract_investigation_{url_obs.id}",
            "text": f"Analyze {url_obs.value} as per your instructions.",
        }

        try:
            last_response = ""
            with client.stream("POST", endpoint, json=payload) as response:
                response.raise_for_status()
                for chunk in response.iter_text():
                    print(chunk)
                    parsed_event = json.loads(chunk[6:].strip())
                    for part in parsed_event["content"]["parts"]:
                        if "text" in part and not part.get("thought", False):
                            last_response = part["text"]

            parsed_report = json.loads(last_response)
            self.process_report(parsed_report, source=url_obs)

            # Tag as processed and remove the original tag
            url_obs.expire_tag(FILTER_TAG)

        except httpx.HTTPError as e:
            logging.exception(f"HTTP Error processing URL {url_obs.value} with Agent")
            logging.debug(last_response)
        except Exception as e:
            logging.exception(f"Error processing URL {url_obs.value} with Agent")
            logging.debug(last_response)

    def process_report(self, report, source: observable.Url):
        report_entity = investigation.Investigation(
            name=report["title"],
            description=report["summary"],
            reference=source.value,
        ).save()

        for ioc in report["iocs"]:
            obs = observable.save(value=ioc["value"])
            obs.add_context(
                source=self.name, context={"description": ioc["description"]}
            )
            report_entity.link_to(obs, "contains", ioc["description"])

        logging.info(
            f"Created investigation: {report_entity.id} with {len(report['iocs'])} IOCs"
        )


taskmanager.TaskManager.register_task(UrlExtractInvestigation)
