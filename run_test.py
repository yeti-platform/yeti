from core.schemas import entity
from core import database_arango
import asyncio
from core.schemas import rbac, user, observable, roles
database_arango.db.connect(database="yeti_test", host="localhost", port=8529)

print("Starting test")
database_arango.db.truncate()

user1 = user.User(username="user1").save()
entity1 = entity.Malware(name="malware1").save()
observable1 = observable.Hostname(value="test.com").save()
observable1.link_to(entity1, "test", description="test")

database_arango.RBAC_ENABLED = True
user1.link_to_acl(entity1, roles.Role.READER)
user1.link_to_acl(observable1, roles.Role.READER)

graph_queries = [("links", "links", "inbound", "name")]

entities, total = entity.Entity.filter({"name": "malware1"}, user=user1, graph_queries=graph_queries)

print("Entities:", entities)
if hasattr(entities[0], 'links'):
    print("Links length:", len(entities[0].links))
    print("Links content:", entities[0].links)
else:
    print("No links attribute")
