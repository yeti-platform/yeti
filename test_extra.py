from core.schemas import entity
from core import database_arango
import asyncio

database_arango.db.connect(database="yeti_test")
database_arango.db.truncate()

malware = entity.Malware(name="malware1").save()
print(malware.model_extra)
