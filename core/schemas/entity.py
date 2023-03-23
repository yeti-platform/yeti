import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel, Field
from core import database_arango

def now():
    return datetime.datetime.now(datetime.timezone.utc)


class Entity(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'entities'
    _type_filter: str = ''

    id: str | None = None
    name: str
    description: str = ''
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    relevant_tags: list[str] = []

    @classmethod
    def load(cls, object: dict):
        if object['type'] in TYPE_MAPPING:
            return TYPE_MAPPING[object['type']](**object)
        return cls(**object)


class ThreatActor(Entity):
    _type_filter: str = 'threat-actor'

    type: str = Field('threat-actor', const=True)
    aliases: list[str] = []

class IntrusionSet(Entity):
    _type_filter: str = 'intrusion-set'
    type: str = Field('intrusion-set', const=True)

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Tool(Entity):
    _type_filter: str = 'tool'
    type: str = Field('tool', const=True)

    kill_chain_phases: list[str] = []
    tool_version: str = ''

class Malware(Entity):
    _type_filter: str = 'malware'
    type: str = Field('malware', const=True)

    kill_chain_phases: list[str] = []

class Campaign(Entity):
    _type_filter: str = 'campaign'
    type: str = Field('campaign', const=True)

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)

TYPE_MAPPING = {
    'threat-actor': ThreatActor,
    'intrusion-set': IntrusionSet,
    'tool': Tool,
    'malware': Malware,
    'campaign': Campaign,
    'entities': Entity,
}
