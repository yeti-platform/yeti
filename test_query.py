user_admin = False
RBAC_ENABLED = True
user = True

neighbor_acl_filter = ""
if user and RBAC_ENABLED and not user_admin:
    neighbor_acl_filter = "FILTER FIRST(FOR aclv IN 1..2 INBOUND v acls FILTER aclv.username == @username RETURN true) OR false"

graph_queries = [("links", "links", "inbound", "name")]

graph_query_string = ""
for name, graph, direction, field in graph_queries:
    field_aggregation = "||".join([f"v.{field}" for field in field.split("|")])
    graph_query_string += f"\nLET {name} = (FOR v, e in 1..1 {direction} o {graph} {neighbor_acl_filter} RETURN {{ [{field_aggregation}]: e }})"

print(graph_query_string)
