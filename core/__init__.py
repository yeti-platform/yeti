from mongoengine import *

# Necessary to import classes that inherit from ScheduleEntry
from core.exports import Export
from core.feed import Feed
from core.analytics import ScheduledAnalytics

from core.config.config import yeti_config

connect(
    yeti_config.mongodb.database,
    host=yeti_config.mongodb.host,
    port=yeti_config.mongodb.port,
    username=yeti_config.mongodb.username,
    password=yeti_config.mongodb.password,
    connect=False
)
