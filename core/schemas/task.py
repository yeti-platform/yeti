import datetime
import logging
import os
import pathlib
from enum import Enum
from io import BytesIO
from typing import ClassVar, Literal
from zipfile import ZipFile

import boto3
import numpy as np
import pandas as pd
import requests
from dateutil import parser
from pydantic import BaseModel, Field

from core import database_arango
from core.config.config import yeti_config
from core.schemas.model import YetiModel
from core.schemas.observable import Observable, ObservableType
from core.schemas.template import Template

if yeti_config.get("system", "export_path", "/opt/yeti/exports").startswith("s3://"):
    s3_client = boto3.client("s3")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


class TaskStatus(str, Enum):
    idle = "idle"
    running = "running"
    completed = "completed"
    failed = "failed"


class TaskType(str, Enum):
    feed = "feed"
    analytics = "analytics"
    export = "export"
    oneshot = "oneshot"
    inline = "inline"


class TaskParams(BaseModel):
    params: dict = Field(default_factory=dict)


class Task(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "tasks"
    _type_filter: ClassVar[str] = ""
    _defaults: ClassVar[dict] = {}

    # id: str | None = None
    name: str
    enabled: bool = False
    description: str = ""
    status: TaskStatus = TaskStatus.idle
    status_message: str = ""
    last_run: datetime.datetime | None = None

    # only used for cron tasks
    frequency: datetime.timedelta | None = None

    def run(self, params: dict):
        """Runs the task"""
        raise NotImplementedError("run() must be implemented in subclass")

    @classmethod
    def load(cls, object: dict) -> "TaskTypes":
        # If this is called using Task, then return a Task or AnalyticsTask
        if cls == Task and object["type"] in TYPE_MAPPING:
            cls = TYPE_MAPPING[object["type"]]
        # Otherwise, use the actual cls.
        return cls(**object)


class FeedTask(Task):
    type: Literal[TaskType.feed] = TaskType.feed

    def add_feed_context(self, observable: Observable, context: dict) -> None:
        """Adds context to an observable."""
        observable.add_context(source=f"feed:{self.name}", context=context)

    def _unzip_content(self, content: bytes) -> bytes:
        """Unzip the content of a response.

        Args:
            content: The content to unzip.

        Returns:
            The unzipped content.
        """
        f = ZipFile(BytesIO(content))
        name = f.namelist()[0]
        return f.read(name)

    def _filter_observables_by_time(
        self, df: pd.DataFrame, column: str
    ) -> pd.DataFrame:
        """Filter a dataframe by comparing the datetime in a column to the last run time.

        Args:
            df: The dataframe to filter.
            column: The column containing the datetime to compare.

        Returns:
            A filtered dataframe.
        """
        if self.last_run:
            logging.debug(f"Filtering {len(df)} observables by time.")
            logging.debug(f"Last run: {self.last_run}")
            logging.debug(f"Column: {column}")
            df = df[df[column] > np.datetime64(self.last_run)]
        return df

    def _make_request(
        self,
        url: str,
        method: str = "get",
        headers: dict = {},
        auth: tuple = (),
        params: dict = {},
        data: dict = {},
        json_data: dict = {},
        verify: bool = True,
        sort: bool = True,
        no_cache: bool = False,
    ) -> requests.Response | None:
        """Helper function. Performs an HTTP request on ``source`` and returns request object.

        Args:
            method: Optional HTTP method to use, e.g. "get" or "post".
            headers: Optional headers to be added to the HTTP request.
            auth: Username / password tuple to be sent along with the HTTP request.
            params: Optional param to be added to the HTTP GET request.
            data: Optional param to be added to the HTTP POST request.
            verify: Enforce (True) or skip (False) SSL verification.
            no_cache: Return the requests content even if they're older than the last run.

        Returns:
            requests object.
        """
        if json_data:
            response = getattr(requests, method.lower())(
                url,
                headers=headers,
                auth=auth,
                proxies=yeti_config.get("proxy"),
                params=params,
                json=json_data,
                verify=verify,
                stream=True,
            )
        else:
            response = getattr(requests, method.lower())(
                url,
                headers=headers,
                auth=auth,
                proxies=yeti_config.get("proxy"),
                params=params,
                data=data,
                verify=verify,
                stream=True,
            )

        if response.status_code != 200:
            raise RuntimeError(f"{url} returned code: {response.status_code}")

        if not sort:
            return response

        if no_cache:
            return response

        last_modified_header = response.headers.get("Last-Modified")
        if self.last_run is not None and last_modified_header:
            last_modified = parser.parse(last_modified_header)
            if self.last_run > last_modified:
                msg = (
                    f"{url}: Last-Modified header ({last_modified_header}) "
                    "before last-run ({self.last_run})"
                )
                logging.debug(msg)
                return

        return response


class AnalyticsTask(Task):
    acts_on: list[str] = []  # By default act on all observables
    type: Literal[TaskType.analytics] = TaskType.analytics

    def run(self):
        """Filters observables to analyze and then calls each()"""
        targets, _ = Observable.filter(query_args={"type__in": self.acts_on})
        self.bulk(targets)

    def bulk(self, observables: list[Observable]):
        """Analyzes a set of observables. Can be overriden if needed."""
        for observable in observables:
            assert observable.id is not None
            self.each(observable)
            self.analysis_done(observable.id)

    def analysis_done(self, observable_id: str):
        """Updates the status of the analysis for a given observable"""
        # TODO: Write a function that just updates a single field.
        observable = Observable.get(observable_id)
        assert observable is not None
        observable.last_analysis[self.name] = now()
        observable.save()

    def each(self, observable: Observable) -> Observable:
        """Analyzes a single observable.

        Args:
            observable: The observable to analyze.

        Returns:
            The observable that was processed, to track last analysis."""
        raise NotImplementedError


class OneShotTask(Task):
    type: Literal[TaskType.oneshot] = TaskType.oneshot
    acts_on: list[str] = []  # By default act on all observables

    def run(self, params: dict):
        """Runs the task.

        By default, we extract the 'value' parameter and get the corresponding
        observable which we pass to each().

        Args:
            params: Parameters to run the task with.
        """
        results, count = Observable.filter(
            query_args={"type__in": self.acts_on, "value": params["value"]}
        )
        if not count:
            logging.warning(
                f"Could not find observable with value {params['value']} with type in {self.acts_on}"
            )
            return
        self.each(results[0])

    def each(self, observable: Observable) -> None:
        """Analyzes a single observable.

        Args:
            observable: The observable to analyze.
        """
        raise NotImplementedError


class ExportTask(Task):
    type: Literal[TaskType.export] = TaskType.export

    include_tags: list[str] = []
    exclude_tags: list[str] = []
    ignore_tags: list[str] = []
    fresh_tags: bool = True
    acts_on: list[ObservableType] = []
    template_name: str
    sha256: str | None = None

    @property
    def file_path(self) -> str:
        """Returns the output file for the export."""
        export_path = yeti_config.get("system", "export_path", "/opt/yeti/exports")
        name_slug = self.name.replace(" ", "_").lower()
        path = os.path.join(export_path, name_slug)

        if path.startswith("s3://"):
            return path
        return os.path.abspath(path)

    def run(self) -> None:
        """Runs the export asynchronously."""
        export_data = self.get_tagged_data(
            acts_on=self.acts_on,
            include_tags=self.include_tags,
            exclude_tags=self.exclude_tags,
            ignore_tags=self.ignore_tags,
            fresh_tags=self.fresh_tags,
        )
        config_path = yeti_config.get("system", "export_path", "/opt/yeti/exports")
        if not config_path.startswith("s3://"):
            export_path = pathlib.Path(config_path)
            export_path.mkdir(parents=True, exist_ok=True)

        template = Template.find(name=self.template_name)
        assert template is not None
        logging.info(f"Rendering template {template.name} to {self.file_path}")

        if self.file_path.startswith("s3://"):
            bucket_name = self.file_path.removeprefix("s3://").split("/")[0]
            key = self.file_path.removeprefix(f"s3://{bucket_name}").removeprefix("/")
            s3_client.put_object(
                Bucket=bucket_name, Key=key, Body=template.render(export_data, None)
            )
            logging.info(f"Succesfully uploaded {self.file_path}")
        else:
            template.render(export_data, self.file_path)
        # hash output file and store result

    @property
    def file_contents(self) -> bytes:
        if self.file_path.startswith("s3://"):
            bucket_name = self.file_path.removeprefix("s3://").split("/")[0]
            key = self.file_path.removeprefix(f"s3://{bucket_name}").removeprefix("/")
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            return response["Body"].read()
        with open(self.file_path, "rb") as f:
            return f.read()

    def get_tagged_data(
        self,
        acts_on: list[str],
        include_tags: list[str],
        exclude_tags: list[str],
        ignore_tags: list[str],
        fresh_tags: bool,
    ):
        args = {
            "acts_on": acts_on,
            "include": include_tags,
            "exclude": exclude_tags,
            "ignore": ignore_tags,
            "fresh": fresh_tags,
        }

        results = database_arango.tagged_observables_export(Observable, args)
        return results


TYPE_MAPPING = {
    "feed": FeedTask,
    "analytics": AnalyticsTask,
    "oneshot": OneShotTask,
    "export": ExportTask,
}


TaskTypes = FeedTask | AnalyticsTask | OneShotTask | ExportTask
