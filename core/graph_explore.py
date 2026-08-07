from __future__ import annotations

from typing import Any, Literal, cast

from arango.exceptions import AQLQueryExecuteError

from core import database_arango
from core.schemas import graph, user

GRAPH_QUERY_MAX_RUNTIME_SECONDS = 10.0
ROOT_COLLECTIONS = {
    "observable": "observables",
    "entity": "entities",
    "indicator": "indicators",
    "dfiq": "dfiq",
}


def _is_timeout(error: AQLQueryExecuteError) -> bool:
    message = str(error).lower()
    return error.error_code == 1500 or "max runtime" in message or "killed" in message


def _execute_aql(query: str, bind_vars: dict[str, Any]) -> list[Any]:
    try:
        return list(
            database_arango.db.aql.execute(
                query,
                bind_vars=bind_vars,
                max_runtime=GRAPH_QUERY_MAX_RUNTIME_SECONDS,
            )
        )
    except AQLQueryExecuteError as error:
        if _is_timeout(error):
            raise TimeoutError from error
        raise


def _filter_aql(filters: list[graph.GraphExploreFilter], args: dict[str, Any]) -> str:
    clauses = []
    for index, graph_filter in enumerate(filters):
        key = f"filter_key_{index}"
        value = f"filter_value_{index}"
        args[key] = graph_filter.key
        args[value] = graph_filter.value
        if graph_filter.operator == "==":
            condition = f"(edge[@{key}] == @{value} OR vertex[@{key}] == @{value})"
        elif graph_filter.operator == "=~":
            condition = (
                f"(REGEX_TEST(edge[@{key}], @{value}, true) "
                f"OR REGEX_TEST(vertex[@{key}], @{value}, true))"
            )
        else:
            condition = (
                f"(@{value} IN TO_ARRAY(edge[@{key}]) "
                f"OR @{value} IN TO_ARRAY(vertex[@{key}]))"
            )
        if graph_filter.pathcompare == "NONE":
            condition = f"NOT {condition}"
        clauses.append(f"FILTER {condition}")
    return "\n                ".join(clauses)


def _item_rows(
    request: graph.GraphExploreRequest,
    scope: graph.GraphExploreItemScope,
    current_user: user.User,
) -> dict[str, list[dict[str, Any]]]:
    args: dict[str, Any] = {
        "anchor_ids": scope.items,
        "rbac_bypass": (not database_arango.RBAC_ENABLED or bool(current_user.admin)),
        "username": current_user.username,
        # In an ANY traversal, a relationship between two anchors can be
        # returned once from each endpoint. Fetch enough rows to observe one
        # unique relationship beyond the requested budget after de-duplication.
        "row_limit": 2 * (request.requested_limits.edges + 1),
    }
    link_filter = ""
    if request.link_types:
        args["link_types"] = request.link_types
        link_filter = "FILTER edge.type IN @link_types"
    target_filter = (
        "FILTER vertex.type IN @target_types OR vertex.root_type IN @target_types"
        if request.target_types
        else ""
    )
    if request.target_types:
        args["target_types"] = request.target_types
    graph_filters = _filter_aql(request.filters, args)
    direction = request.direction.upper()
    query = f"""
        WITH observables, entities, indicators, dfiq, acls
        LET anchors = (
            FOR anchor_id IN @anchor_ids
                LET anchor = DOCUMENT(anchor_id)
                FILTER anchor != null
                FILTER @rbac_bypass OR LENGTH(
                    FOR principal IN 1..2 INBOUND anchor acls
                        FILTER principal.username == @username
                        LIMIT 1
                        RETURN 1
                ) > 0
                RETURN KEEP(
                    anchor, "_id", "root_type", "type", "name", "value"
                )
        )
        LET rows = (
            FOR origin IN anchors
                LET origin_index = POSITION(@anchor_ids, origin._id)
                FOR vertex, edge IN 1..1 {direction} origin links
                FILTER @rbac_bypass OR LENGTH(
                    FOR principal IN 1..2 INBOUND vertex acls
                        FILTER principal.username == @username
                        LIMIT 1
                        RETURN 1
                ) > 0
                {link_filter}
                {target_filter}
                {graph_filters}
                SORT origin_index ASC, edge._id ASC
                LIMIT @row_limit
                RETURN {{
                    origin_id: origin._id,
                    vertex: KEEP(
                        vertex, "_id", "root_type", "type", "name", "value"
                    ),
                    edge: KEEP(
                        edge, "_id", "_from", "_to", "type", "description", "count"
                    )
                }}
        )
        RETURN {{anchors, rows}}
    """
    result = _execute_aql(query, args)
    return result[0] if result else {"anchors": [], "rows": []}


def _extended_id(document: dict[str, Any]) -> str:
    root_type = str(document.get("root_type", ""))
    collection = ROOT_COLLECTIONS.get(root_type)
    if collection is None:
        raise ValueError("Unsupported object type in query scope")
    return f"{collection}/{document['id']}"


def _induced_edges(
    ids: list[str], request: graph.GraphExploreRequest
) -> list[dict[str, Any]]:
    if not ids:
        return []
    args: dict[str, Any] = {
        "ids": ids,
        "row_limit": request.requested_limits.edges + 1,
    }
    link_filter = ""
    if request.link_types:
        args["link_types"] = request.link_types
        link_filter = "FILTER edge.type IN @link_types"
    target_filter = (
        "FILTER vertex.type IN @target_types OR vertex.root_type IN @target_types"
        if request.target_types
        else ""
    )
    if request.target_types:
        args["target_types"] = request.target_types
    graph_filters = _filter_aql(request.filters, args)
    query = f"""
        WITH observables, entities, indicators, dfiq
        FOR edge IN links
            FILTER edge._from IN @ids AND edge._to IN @ids
            LET vertex = DOCUMENT(edge._to)
            {link_filter}
            {target_filter}
            {graph_filters}
            SORT edge._id ASC
            LIMIT @row_limit
            RETURN KEEP(
                edge, "_id", "_from", "_to", "type", "description", "count"
            )
    """
    return _execute_aql(query, args)


def _node(
    document: dict[str, Any],
    role: Literal["anchor", "scope_match", "neighbor"],
    origin_ids: list[str],
) -> graph.GraphExploreNode:
    identifier = str(document.get("_id") or _extended_id(document))
    label = next(
        (
            str(document[field])
            for field in ("value", "name")
            if document.get(field) not in (None, "")
        ),
        identifier,
    )
    return graph.GraphExploreNode(
        id=identifier,
        label=label,
        root_type=str(document.get("root_type", "unknown")),
        object_type=str(document.get("type") or document.get("root_type", "unknown")),
        role=role,
        origin_ids=origin_ids,
    )


def _edge(document: dict[str, Any]) -> graph.GraphExploreEdge:
    return graph.GraphExploreEdge(
        id=str(document["_id"]),
        source=str(document["_from"]),
        target=str(document["_to"]),
        type=str(document.get("type", "related")),
        description=str(document.get("description", "")),
        count=int(document.get("count", 1)),
    )


def _budget(
    request: graph.GraphExploreRequest,
    nodes: list[graph.GraphExploreNode],
    edges: list[graph.GraphExploreEdge],
    reasons: set[str],
) -> graph.GraphExploreBudget:
    ordered_reasons = [
        cast("Any", reason)
        for reason in ("node_limit", "edge_limit")
        if reason in reasons
    ]
    return graph.GraphExploreBudget(
        node_limit=request.requested_limits.nodes,
        edge_limit=request.requested_limits.edges,
        returned_nodes=len(nodes),
        returned_edges=len(edges),
        is_truncated=bool(ordered_reasons),
        reasons=ordered_reasons,
    )


def _explore_items(
    request: graph.GraphExploreRequest,
    scope: graph.GraphExploreItemScope,
    current_user: user.User,
) -> graph.GraphExploreResponse:
    result = _item_rows(request, scope, current_user)
    anchors = result["anchors"]
    if [anchor["_id"] for anchor in anchors] != scope.items:
        raise LookupError

    reasons: set[str] = set()
    node_limit = request.requested_limits.nodes
    edge_limit = request.requested_limits.edges
    nodes_by_id: dict[str, graph.GraphExploreNode] = {}
    anchor_ids = set(scope.items)
    for anchor in anchors:
        if len(nodes_by_id) >= node_limit:
            reasons.add("node_limit")
            break
        identifier = str(anchor["_id"])
        nodes_by_id[identifier] = _node(anchor, "anchor", [identifier])

    edges_by_id: dict[str, graph.GraphExploreEdge] = {}
    rows = result["rows"]
    for row in rows:
        edge = _edge(row["edge"])
        if edge.id not in edges_by_id and len(edges_by_id) >= edge_limit:
            reasons.add("edge_limit")
            continue

        origin_id = str(row["origin_id"])
        vertex = row["vertex"]
        vertex_id = str(vertex["_id"])
        existing = nodes_by_id.get(vertex_id)
        if existing is not None:
            if origin_id not in existing.origin_ids:
                existing.origin_ids.append(origin_id)
        elif len(nodes_by_id) < node_limit:
            role = "anchor" if vertex_id in anchor_ids else "neighbor"
            origins = [vertex_id] if role == "anchor" else []
            if origin_id not in origins:
                origins.append(origin_id)
            nodes_by_id[vertex_id] = _node(vertex, role, origins)
        else:
            reasons.add("node_limit")
            continue

        if edge.source not in nodes_by_id or edge.target not in nodes_by_id:
            continue
        if edge.id in edges_by_id:
            continue
        edges_by_id[edge.id] = edge

    nodes = list(nodes_by_id.values())
    edges = list(edges_by_id.values())
    return graph.GraphExploreResponse(
        scope=graph.GraphExploreScopeResult(
            kind="items",
            anchor_ids=scope.items,
            accessible_match_count=len(scope.items),
            ranking=None,
        ),
        nodes=nodes,
        edges=edges,
        budget=_budget(request, nodes, edges, reasons),
    )


def _explore_query(
    request: graph.GraphExploreRequest,
    scope: graph.GraphExploreQueryScope,
    current_user: user.User,
) -> graph.GraphExploreResponse:
    ranking = list(scope.sorting) if scope.sorting else [("modified", False)]
    if not any(field == "_id" for field, _ in ranking):
        ranking.append(("_id", True))
    try:
        candidates, total = database_arango.ArangoYetiConnector.filter(
            scope.query,
            sorting=ranking,
            aliases=cast("list[tuple[str, str]]", scope.filter_aliases),
            count=request.requested_limits.nodes + 1,
            user=current_user,
            max_runtime=GRAPH_QUERY_MAX_RUNTIME_SECONDS,
        )
    except AQLQueryExecuteError as error:
        if _is_timeout(error):
            raise TimeoutError from error
        raise
    documents = cast("list[dict[str, Any]]", candidates)
    reasons: set[str] = set()
    if total > request.requested_limits.nodes:
        reasons.add("node_limit")
    documents = documents[: request.requested_limits.nodes]
    nodes = [
        _node(document, "scope_match", [_extended_id(document)])
        for document in documents
    ]
    edges_raw = _induced_edges([node.id for node in nodes], request)
    if len(edges_raw) > request.requested_limits.edges:
        reasons.add("edge_limit")
    edges = [
        _edge(document) for document in edges_raw[: request.requested_limits.edges]
    ]
    return graph.GraphExploreResponse(
        scope=graph.GraphExploreScopeResult(
            kind="query",
            anchor_ids=[],
            accessible_match_count=total,
            ranking=ranking,
        ),
        nodes=nodes,
        edges=edges,
        budget=_budget(request, nodes, edges, reasons),
    )


def explore_graph(
    request: graph.GraphExploreRequest, current_user: user.User
) -> graph.GraphExploreResponse:
    if isinstance(request.scope, graph.GraphExploreItemScope):
        return _explore_items(request, request.scope, current_user)
    return _explore_query(request, request.scope, current_user)
