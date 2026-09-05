import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import rbac, roles, user
from core.schemas.agent_persona import AgentPersona
from core.web import webapp

client = TestClient(webapp.app)

INSTRUCTION = "You are a threat intelligence analyst. Be concise and cite sources."


def persona_payload(name: str, **overrides) -> dict:
    payload = {
        "name": name,
        "description": f"{name} persona",
        "instruction": INSTRUCTION,
        "tools": [],
        "enabled": True,
        "default": False,
    }
    payload.update(overrides)
    return {"persona": payload}


class AgentPersonaTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

        u = user.UserSensitive(username="test", password="test", enabled=True).save()
        apikey = u.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def test_create_and_fetch(self) -> None:
        response = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("analyst")
        )
        self.assertEqual(response.status_code, 200, response.text)
        created = response.json()
        self.assertEqual(created["name"], "analyst")
        self.assertEqual(created["instruction"], INSTRUCTION)

        response = client.get(f"/api/v2/agentpersonas/{created['id']}")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["name"], "analyst")

    def test_duplicate_name_is_rejected(self) -> None:
        """Personas are referenced by name from the chat, so two with the same
        name would make which one answers arbitrary."""
        client.post("/api/v2/agentpersonas/", json=persona_payload("analyst"))

        response = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("analyst")
        )

        self.assertEqual(response.status_code, 409, response.text)

    def test_short_instruction_is_rejected_on_write(self) -> None:
        """An instruction is the agent's whole behaviour. Caught at save time
        rather than surfacing later as what looks like a model failure."""
        response = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("thin", instruction="hi")
        )

        self.assertEqual(response.status_code, 422, response.text)

    def test_patch_updates_the_instruction(self) -> None:
        created = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("analyst")
        ).json()
        updated = dict(created)
        updated["instruction"] = "A completely different set of standing instructions."

        response = client.patch(
            f"/api/v2/agentpersonas/{created['id']}", json={"persona": updated}
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json()["instruction"],
            "A completely different set of standing instructions.",
        )

    def test_only_one_persona_is_default(self) -> None:
        """Enforced against the personas themselves rather than a separate
        setting, which could disagree with them."""
        first = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("first", default=True)
        ).json()
        second = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("second", default=True)
        ).json()

        self.assertTrue(second["default"])
        self.assertFalse(
            client.get(f"/api/v2/agentpersonas/{first['id']}").json()["default"]
        )

    def test_promoting_a_default_by_patch_demotes_the_previous_one(self) -> None:
        first = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("first", default=True)
        ).json()
        second = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("second")
        ).json()

        promoted = dict(second)
        promoted["default"] = True
        client.patch(
            f"/api/v2/agentpersonas/{second['id']}", json={"persona": promoted}
        )

        self.assertFalse(
            client.get(f"/api/v2/agentpersonas/{first['id']}").json()["default"]
        )

    def test_the_default_persona_cannot_be_deleted(self) -> None:
        """Deleting it would leave requests naming no persona with nothing to
        fall back to, and the agents service would quietly revert to its
        built-in instructions."""
        created = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("only", default=True)
        ).json()

        response = client.delete(f"/api/v2/agentpersonas/{created['id']}")

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            client.get(f"/api/v2/agentpersonas/{created['id']}").status_code, 200
        )

    def test_a_non_default_persona_can_be_deleted(self) -> None:
        created = client.post(
            "/api/v2/agentpersonas/", json=persona_payload("temporary")
        ).json()

        response = client.delete(f"/api/v2/agentpersonas/{created['id']}")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            client.get(f"/api/v2/agentpersonas/{created['id']}").status_code, 404
        )

    def test_search_filters_by_enabled(self) -> None:
        client.post("/api/v2/agentpersonas/", json=persona_payload("live"))
        client.post(
            "/api/v2/agentpersonas/", json=persona_payload("retired", enabled=False)
        )

        response = client.post("/api/v2/agentpersonas/search", json={"enabled": True})

        self.assertEqual(response.status_code, 200, response.text)
        names = [p["name"] for p in response.json()["personas"]]
        self.assertIn("live", names)
        self.assertNotIn("retired", names)

    def test_search_pages_within_the_filtered_set(self) -> None:
        for i in range(5):
            client.post("/api/v2/agentpersonas/", json=persona_payload(f"live{i}"))
        for i in range(3):
            client.post(
                "/api/v2/agentpersonas/",
                json=persona_payload(f"off{i}", enabled=False),
            )

        response = client.post(
            "/api/v2/agentpersonas/search",
            json={"enabled": True, "count": 2, "page": 0},
        )

        body = response.json()
        self.assertEqual(body["total"], 5, body)
        self.assertEqual(len(body["personas"]), 2, body)
        self.assertTrue(all(p["enabled"] for p in body["personas"]), body)

    def test_tools_are_stored_as_names(self) -> None:
        """Names rather than definitions, so a persona can decline capability
        but never invent it."""
        response = client.post(
            "/api/v2/agentpersonas/",
            json=persona_payload("scoped", tools=["semantic_search"]),
        )

        self.assertEqual(response.json()["tools"], ["semantic_search"])


class AgentPersonaRbacTest(unittest.TestCase):
    """Editing a persona changes how the agent behaves for everyone using it,
    so it is an administrative act rather than a per-user preference."""

    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

        # New users get the configured default global role, which is "writer",
        # so a read-only user has to be made one explicitly.
        self.reader = user.UserSensitive(
            username="reader", global_role=roles.Role.READER
        ).save()
        apikey = self.reader.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        self.reader_token = token_data["access_token"]

    def tearDown(self) -> None:
        rbac.RBAC_ENABLED = False
        database_arango.RBAC_ENABLED = False

    def test_creating_a_persona_requires_write(self) -> None:
        response = client.post(
            "/api/v2/agentpersonas/",
            json=persona_payload("sneaky"),
            headers={"Authorization": f"Bearer {self.reader_token}"},
        )

        self.assertEqual(response.status_code, 403, response.text)


if __name__ == "__main__":
    unittest.main()
