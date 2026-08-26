import json
import logging
from datetime import timedelta

import httpx
from pydantic import BaseModel, ValidationError

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import observable, task
from core.schemas.entities import investigation

AGENT_HTTP_BASE = yeti_config.get("agents", "http_root")
AGENT_STREAM_ENDPOINT = f"{AGENT_HTTP_BASE}/run_stream?agent_name=ioc_analyzer"

FILTER_TAG = "extract_iocs"

SSE_DATA_PREFIX = "data:"

# The ioc_analyzer agent declares an ADK output_schema, so its final message is
# JSON matching the models below. They are deliberately a subset of that schema:
# unknown fields (tags, last_updated, external_references) are ignored rather
# than rejected, so the agent can grow its response without breaking ingestion.
#
# The IOC types the agent can emit are its own enum, not Yeti's. Anything not
# mapped here is left to Yeti's guesser.
AGENT_TYPE_MAPPING = {
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "hostname",
    "url": "url",
    "email": "email",
    "other": None,
}


class IOC(BaseModel):
    value: str
    type: str = "other"
    description: str = ""


class AgentReport(BaseModel):
    title: str
    summary: str
    iocs: list[IOC] = []


class IOCExtractor(task.AnalyticsTask):
    _defaults = {
        "name": "IOCExtractor",
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
            "session_id": f"extract_iocs_{url_obs.id}",
            "text": f"Analyze {url_obs.value} as per your instructions.",
        }

        last_response = ""
        try:
            with client.stream("POST", endpoint, json=payload) as response:
                response.raise_for_status()
                # Iterate lines rather than chunks: iter_text() splits on
                # arbitrary boundaries, so a chunk may hold several SSE frames
                # or half of one. Keepalive comments and blank separators are
                # not JSON and are skipped.
                for line in response.iter_lines():
                    line = line.strip()
                    if not line.startswith(SSE_DATA_PREFIX):
                        continue
                    data = line[len(SSE_DATA_PREFIX) :].strip()
                    if not data:
                        continue
                    try:
                        parsed_event = json.loads(data)
                    except json.JSONDecodeError:
                        logging.warning(
                            "Skipping unparseable event from Agent for URL %s",
                            url_obs.value,
                        )
                        continue

                    # The agent reports its own failures as an event rather than
                    # an HTTP error; surface the reason instead of letting the
                    # missing content key look like a parsing bug.
                    if "error" in parsed_event:
                        logging.error(
                            "Agent reported an error processing URL %s: %s (%s)",
                            url_obs.value,
                            parsed_event.get("error"),
                            parsed_event.get("error_type", "unknown"),
                        )
                        return

                    for part in parsed_event.get("content", {}).get("parts", []):
                        if "text" in part and not part.get("thought", False):
                            last_response = part["text"]

            try:
                parsed_report = AgentReport.model_validate_json(last_response)
            except ValidationError:
                logging.error(
                    "Agent response for URL %s did not match the expected schema; "
                    "no objects were created.",
                    url_obs.value,
                )
                logging.debug(last_response)
                return

            self.process_report(parsed_report, source=url_obs)

            url_obs.expire_tag(FILTER_TAG)

        except httpx.HTTPError:
            logging.exception(f"HTTP Error processing URL {url_obs.value} with Agent")
            logging.debug(last_response)
        except Exception:
            logging.exception(f"Error processing URL {url_obs.value} with Agent")
            logging.debug(last_response)

    def _build_observable(self, ioc: IOC) -> observable.ObservableTypes | None:
        """Turns an agent IOC into an unsaved observable, or None if it can't be
        trusted.

        The agent supplies a type, so there is no need to guess one. Passing it
        through is not enough on its own: create() will happily build an ipv4
        holding a hostname, so the value is checked against the type it claims
        to be. A mismatch means either the value or the type is wrong, and
        neither is worth storing.
        """
        observable_type = AGENT_TYPE_MAPPING.get(ioc.type)
        try:
            obs = observable.create(value=ioc.value, type=observable_type)
        except ValueError:
            logging.warning(
                "Skipping IOC with unusable value %r (agent type: %s)",
                ioc.value,
                ioc.type,
            )
            return None

        if not obs.is_valid:
            logging.warning(
                "Skipping IOC %r: value does not match the type the agent "
                "reported (%s)",
                ioc.value,
                ioc.type,
            )
            return None

        return obs

    def process_report(self, report: AgentReport, source: observable.Observable):
        # Build every observable before writing anything. Saving the
        # investigation first would leave it orphaned, with a partial set of
        # links, if an IOC further down the list turned out to be unusable.
        valid_iocs = []
        for ioc in report.iocs:
            obs = self._build_observable(ioc)
            if obs is not None:
                valid_iocs.append((obs, ioc.description))

        report_entity = investigation.Investigation(
            name=report.title,
            description=report.summary,
            reference=source.value,
        ).save()

        report_entity.link_to(source, "related_to", "source_url")

        for obs, description in valid_iocs:
            saved_obs = obs.save()
            saved_obs.add_context(
                source=self.name, context={"description": description}
            )
            report_entity.link_to(saved_obs, "contains", description)

        skipped = len(report.iocs) - len(valid_iocs)
        logging.info(
            "Created investigation: %s with %d IOCs (%d skipped)",
            report_entity.id,
            len(valid_iocs),
            skipped,
        )


taskmanager.TaskManager.register_task(IOCExtractor)
