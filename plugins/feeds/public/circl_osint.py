"""CIRCL OSINT feed, published in the MISP feed format.

A MISP-format feed is a directory of static files: ``manifest.json`` lists
every event with its organisation, tags and last-modified timestamp, and each
event is a ``<uuid>.json`` file holding a MISP event. The parsing functions
below take and return plain dicts so they can be tested without a database;
the feed task fetches the files and stores the observables.
"""

import datetime
import logging
from typing import ClassVar, Collection, Iterator, NamedTuple

from requests.exceptions import RequestException

from core import taskmanager
from core.common.misp_to_yeti import MISP_TYPES_TO_IMPORT
from core.schemas import model, observable, task

EXTERNAL_ANALYSIS = "External analysis"
LINK_TYPES = {"url", "link"}


def select_events(
    manifest: dict, since: datetime.datetime, skip_tags: Collection[str]
) -> list[str]:
    """Returns the uuids of the events updated at or after ``since``, oldest
    first, leaving out events carrying any of ``skip_tags``."""
    cutoff = int(since.timestamp())
    skipped = set(skip_tags)
    selected = []
    for uuid, entry in manifest.items():
        timestamp = int(entry.get("timestamp", 0))
        if timestamp < cutoff:
            continue
        tags = {tag.get("name") for tag in entry.get("Tag") or []}
        if tags & skipped:
            continue
        selected.append((timestamp, uuid))
    return [uuid for _, uuid in sorted(selected)]


def event_attributes(event: dict) -> Iterator[tuple[dict, dict | None]]:
    """Yields every attribute of an event with its parent object, or None for
    top-level attributes. Either list can be missing from a feed event."""
    for attribute in event.get("Attribute") or []:
        yield attribute, None
    for obj in event.get("Object") or []:
        for attribute in obj.get("Attribute") or []:
            yield attribute, obj


class ParsedAttribute(NamedTuple):
    type: str
    value: str
    context: dict


def parse_attribute(attribute: dict) -> ParsedAttribute | None:
    """Maps a MISP attribute to a Yeti observable type and value, or returns
    None when the attribute should not become an observable."""
    if attribute.get("deleted") or not attribute.get("to_ids"):
        return None
    if attribute.get("category") == EXTERNAL_ANALYSIS:
        return None
    misp_type = attribute.get("type", "")
    yeti_type = MISP_TYPES_TO_IMPORT.get(misp_type)
    if yeti_type is None:
        return None
    value = str(attribute.get("value", "")).strip()
    context = {}
    if "|" in misp_type:
        # Composite "filename|<hash>" attributes hold "<name>|<hash>".
        filename, _, value = value.rpartition("|")
        context["filename"] = filename
    return ParsedAttribute(yeti_type.value, value, context)


def external_sources(event: dict) -> list[str]:
    """Returns the External analysis links of an event, whatever their
    to_ids flag. They go into context, not into observables."""
    return [
        attribute["value"]
        for attribute, _ in event_attributes(event)
        if attribute.get("category") == EXTERNAL_ANALYSIS
        and attribute.get("type") in LINK_TYPES
    ]


def event_context(event: dict, base_url: str) -> dict:
    """The part of an observable's context shared by every attribute of an
    event. Compute it once per event."""
    uuid = event.get("uuid")
    context = {
        "event_uuid": uuid,
        "info": event.get("info"),
        "date": event.get("date"),
        "org": (event.get("Orgc") or {}).get("name"),
        "link": f"{base_url}{uuid}.json",
    }
    sources = external_sources(event)
    if sources:
        context["external sources"] = "\r\n".join(sources)
    return context


def attribute_context(shared: dict, attribute: dict) -> dict:
    """Adds an attribute's own fields to the event's shared context."""
    context = dict(shared)
    context["category"] = attribute.get("category")
    if attribute.get("comment"):
        context["comment"] = attribute["comment"]
    return context


def attribute_tags(event: dict, attribute: dict) -> list[str]:
    """The event's tags followed by the attribute's own, without repeats."""
    names: list[str] = []
    for tag in (event.get("Tag") or []) + (attribute.get("Tag") or []):
        name = tag.get("name")
        if name and name not in names:
            names.append(name)
    return names


class MispFeedFormat(task.FeedTask):
    """A feed published in the MISP feed format. Subclasses set the URL."""

    # URL of the feed directory, ending with "/".
    _SOURCE: ClassVar[str] = ""
    # How far back the first run looks.
    _HISTORY: ClassVar[datetime.timedelta] = datetime.timedelta(days=60)
    # Later runs re-check events updated this long before the last run: the
    # manifest is regenerated on the publisher's schedule, so an event changed
    # shortly before a run can show up in the manifest only after it.
    _OVERLAP: ClassVar[datetime.timedelta] = datetime.timedelta(days=1)
    # Events carrying any of these tags are not fetched.
    _SKIP_TAGS: ClassVar[frozenset[str]] = frozenset()
    # Tags added to every observable.
    _TAGS: ClassVar[tuple[str, ...]] = ()

    def run(self):
        response = self._make_request(f"{self._SOURCE}manifest.json")
        if response is None:
            logging.info(f"{self.name}: manifest not modified since the last run")
            return
        manifest = response.json()
        if self.last_run:
            since = self.last_run - self._OVERLAP
        else:
            since = datetime.datetime.now(datetime.timezone.utc) - self._HISTORY
        uuids = select_events(manifest, since, self._SKIP_TAGS)
        logging.info(
            f"{self.name}: {len(uuids)} of {len(manifest)} events updated "
            f"since {since:%Y-%m-%d}"
        )
        for uuid in uuids:
            event = self.fetch_event(uuid)
            if event is not None:
                self.analyze_event(event)

    def fetch_event(self, uuid: str) -> dict | None:
        """Returns one event, or None when its file can't be fetched or read.
        One bad file shouldn't fail the whole run."""
        try:
            response = self._make_request(f"{self._SOURCE}{uuid}.json", sort=False)
            if response is None:
                return None
            return response.json()["Event"]
        except (RuntimeError, ValueError, KeyError, TypeError, RequestException):
            logging.exception(f"{self.name}: could not fetch event {uuid}")
            return None

    def analyze_event(self, event: dict) -> None:
        shared = event_context(event, self._SOURCE)
        # Per object: its name, the link description, and the observables
        # saved from it, which get linked to each other at the end.
        members: dict[str, tuple[str, str, list[observable.ObservableTypes]]] = {}
        for attribute, obj in event_attributes(event):
            parsed = parse_attribute(attribute)
            if parsed is None:
                continue
            obs = self.save_observable(parsed)
            if obs is None:
                continue
            context = attribute_context(shared, attribute)
            context.update(parsed.context)
            # One context entry per event: a changed event updates its entry.
            obs.add_context(
                self.name, context, skip_compare=set(context) - {"event_uuid"}
            )
            tags = attribute_tags(event, attribute)
            obs.tag([*(tag for tag in tags if model.normalize_name(tag)), *self._TAGS])
            if obj is not None:
                key = obj.get("uuid") or str(id(obj))
                if key not in members:
                    name = obj.get("name") or "object"
                    members[key] = (name, obj.get("comment") or name, [])
                members[key][2].append(obs)
        for name, description, saved in members.values():
            first, *others = saved
            for other in others:
                first.link_to(other, f"linked_by_misp_{name}", description)

    def save_observable(
        self, parsed: ParsedAttribute
    ) -> observable.ObservableTypes | None:
        """Saves the observable, unless its value fails the type's validator:
        create() trusts an explicit type, so the check is done here."""
        value = observable.refang(parsed.value)
        validator = getattr(observable.TYPE_MAPPING[parsed.type], "validator", None)
        if validator is not None and not validator(value):
            logging.warning(f"{self.name}: skipping invalid {parsed.type} {value!r}")
            return None
        return observable.save(value=value, type=parsed.type)


class CirclOsintFeed(MispFeedFormat):
    _defaults = {
        "frequency": datetime.timedelta(hours=12),
        "name": "CirclOsintFeed",
        "description": (
            "OSINT events shared by CIRCL and partner organisations as a MISP feed"
        ),
    }

    _SOURCE: ClassVar[str] = "https://www.circl.lu/doc/misp/feed-osint/"
    # Daily automated dumps (Maltrail, around 12,000 domains each) are left out.
    _SKIP_TAGS: ClassVar[frozenset[str]] = frozenset(
        {'misp:automation-level="unsupervised"'}
    )
    _TAGS: ClassVar[tuple[str, ...]] = ("circl-osint",)


taskmanager.TaskManager.register_task(CirclOsintFeed)
