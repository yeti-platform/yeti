import datetime
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import (
    audit,
    entity,
    indicator,
    observable,
    rbac,
    roles,
    task,
    template,
    user,
)
from core.web import webapp

client = TestClient(webapp.app)


class rbacTest(unittest.TestCase):
    # mock patch the RBAC_ENABLED global of entities.py
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

        self.group1 = rbac.Group(name="test1").save()
        self.group2 = rbac.Group(name="test2").save()
        self.entity1 = entity.Malware(name="test1").save()
        self.entity2 = entity.Malware(name="test2").save()

        self.user1 = user.UserSensitive(username="user1").save()
        user1_apikey = self.user1.create_api_key("default")
        self.user2 = user.UserSensitive(username="user2").save()
        user2_apikey = self.user2.create_api_key("default")
        self.admin = user.UserSensitive(username="yeti", admin=True).save()
        admin_apikey = self.admin.create_api_key("default")

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user1_apikey}
        ).json()
        self.user1_token = token_data["access_token"]

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user2_apikey}
        ).json()
        self.user2_token = token_data["access_token"]

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": admin_apikey}
        ).json()
        self.admin_token = token_data["access_token"]

    def tearDown(self) -> None:
        rbac.RBAC_ENABLED = False
        database_arango.RBAC_ENABLED = False

    def test_role_update_unlocks_resource_user(self) -> None:
        """Test that a user can access a resource"""
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_role_update_unlocks_resource_via_group(self) -> None:
        """Test that a user can access a resource"""
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.group1, roles.Role.OWNER)
        self.group1.link_to_acl(self.entity1, roles.Role.OWNER)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_different_user_doesnt_have_access(self):
        """Test that a user can access a resource"""
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_user_can_tag_entity(self):
        """Test that a user can tag an entity"""
        self.user1.link_to_acl(self.entity1, roles.Role.READER)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["test"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

        self.user1.link_to_acl(self.entity1, roles.Role.WRITER)

        response = client.post(
            "/api/v2/entities/tag",
            json={"ids": [self.entity1.id], "tags": ["test"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer_entity(self):
        """Test that a user can create a new entity"""
        self.user1.global_role = roles.Role.READER
        self.user1.save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer_indicator(self):
        """Test that a user can create a new indicator"""
        self.user1.global_role = roles.Role.READER
        self.user1.save()

        payload = {
            "indicator": {
                "pattern": "test",
                "type": "regex",
                "name": "test",
                "diamond": "victim",
            }
        }
        response = client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_global_writer_observable(self):
        """Test that a user can create a new observable"""
        self.user1.global_role = roles.Role.READER
        self.user1.save()

        payload = {
            "type": "generic",
            "value": "test",
        }

        response = client.post(
            "/api/v2/observables",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 403, data)

        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        response = client.post(
            "/api/v2/observables",
            json=payload,
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_delete_relationship(self):
        """Test that a user can delete a relationship"""
        relationship = self.user1.link_to_acl(self.entity1, roles.Role.OWNER)

        # # assert we can get the entity
        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

        # assert entity shows up in search
        response = client.post(
            "/api/v2/entities/search",
            json={"query": {"name": "test1"}, "type": "malware"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["entities"][0]["name"], "test1")

        response = client.delete(
            f"/api/v2/rbac/{relationship.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200)

        response = client.post(
            "/api/v2/entities/search",
            json={"query": {"name": "test1"}, "type": "malware"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["entities"], [])

        response = client.get(
            f"/api/v2/entities/{self.entity1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_update_members_every_valid_role(self):
        """Every value Role actually declares (0, 1, 3, 7) must be grantable
        through the update-members endpoint, and the granted value must
        round-trip correctly through the ACL response.
        """
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)

        for role in roles.Role:
            with self.subTest(role=role):
                response = client.post(
                    f"/api/v2/rbac/entity/{self.entity1.id}/update-members",
                    json={
                        "ids": [{"id": self.user2.id, "type": "user"}],
                        "role": role,
                    },
                    headers={"Authorization": f"Bearer {self.user1_token}"},
                )
                data = response.json()
                self.assertEqual(response.status_code, 200, data)
                self.assertEqual(data["updated"], 1)
                self.assertEqual(data["failed"], 0)

                response = client.get(
                    f"/api/v2/rbac/entity/{self.entity1.id}",
                    headers={"Authorization": f"Bearer {self.user1_token}"},
                )
                data = response.json()
                self.assertEqual(response.status_code, 200, data)
                self.assertEqual(data["acls"]["user2"]["role"], role)

    def test_update_members_rejects_non_composite_role(self):
        """Values Permission accepts but Role doesn't (2, 4, 5, 6) -- and
        values outside Permission's range entirely (8, -1) -- must be
        rejected with a clean 422, and must not create an ACL edge.
        """
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)

        for invalid_role in (2, 4, 5, 6, 8, -1):
            with self.subTest(invalid_role=invalid_role):
                response = client.post(
                    f"/api/v2/rbac/entity/{self.entity1.id}/update-members",
                    json={
                        "ids": [{"id": self.user2.id, "type": "user"}],
                        "role": invalid_role,
                    },
                    headers={"Authorization": f"Bearer {self.user1_token}"},
                )
                self.assertEqual(response.status_code, 422, response.json())

                response = client.get(
                    f"/api/v2/rbac/entity/{self.entity1.id}",
                    headers={"Authorization": f"Bearer {self.user1_token}"},
                )
                data = response.json()
                self.assertNotIn("user2", data["acls"])

    def test_default_acls(self):
        """Test that a user can create a new entity"""
        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        rbac.Group(name="All users").save()

        response = client.post(
            "/api/v2/entities",
            json={"entity": {"name": "test", "type": "malware"}},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

        test_malware = entity.Malware.find(name="test")
        test_malware.get_acls()
        self.assertCountEqual(test_malware.acls.keys(), ["All users", "user1"])
        # The creator gets full ownership; the default-shared group only gets
        # read access -- default_acls is meant to grant visibility, not hand
        # every registered user delete rights over every new object.
        self.assertEqual(test_malware.acls["All users"].role, roles.Role.READER)
        self.assertEqual(test_malware.acls["user1"].role, roles.Role.OWNER)

    def test_graph_search_enforces_source_and_intermediate_acls(self):
        """Graph search rejects unreadable sources and omits paths traversing
        unreadable intermediate vertices."""
        obs1 = observable.Hostname(value="public1.example.com").save()
        obs2 = observable.Hostname(value="public2.example.com").save()
        secret = entity.Investigation(
            name="secret-case", description="classified"
        ).save()
        self.user1.link_to_acl(obs1, roles.Role.OWNER)
        self.user1.link_to_acl(obs2, roles.Role.OWNER)
        self.user1.link_to_acl(secret, roles.Role.OWNER)
        self.user2.link_to_acl(obs1, roles.Role.READER)
        self.user2.link_to_acl(obs2, roles.Role.READER)
        obs1.link_to(secret, "related", "link1")
        secret.link_to(obs2, "related", "link2")

        # Unreadable source must be refused even with include_original=True.
        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": f"investigation/{secret.id}",
                "hops": 1,
                "graph": "links",
                "direction": "any",
                "include_original": True,
            },
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(response.status_code, 403)

        # Multi-hop traversal from readable obs1 must not leak secret intermediate.
        response = client.post(
            "/api/v2/graph/search",
            json={
                "source": f"hostname/{obs1.id}",
                "min_hops": 1,
                "max_hops": 2,
                "graph": "links",
                "direction": "any",
                "include_original": True,
            },
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertNotIn(secret.extended_id, data["vertices"])
        self.assertEqual(data["paths"], [])

    def test_graph_write_endpoints_enforce_object_acls(self):
        """Graph add/edit/swap/delete require WRITE on both endpoints."""
        obs1 = observable.Hostname(value="user2-obs.example.com").save()
        secret = entity.Investigation(name="restricted-inv").save()
        self.user1.link_to_acl(secret, roles.Role.OWNER)
        self.user2.link_to_acl(obs1, roles.Role.OWNER)
        existing_rel = obs1.link_to(secret, "observed", "initial")

        headers = {"Authorization": f"Bearer {self.user2_token}"}
        self.assertEqual(
            client.post(
                "/api/v2/graph/add",
                json={
                    "source": f"hostname/{obs1.id}",
                    "target": f"investigation/{secret.id}",
                    "link_type": "planted",
                    "description": "planted",
                },
                headers=headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            client.patch(
                f"/api/v2/graph/{existing_rel.id}",
                json={"link_type": "edited", "description": "edited"},
                headers=headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post(
                f"/api/v2/graph/{existing_rel.id}/swap",
                headers=headers,
            ).status_code,
            403,
        )
        self.assertEqual(
            client.delete(
                f"/api/v2/graph/{existing_rel.id}",
                headers=headers,
            ).status_code,
            403,
        )

        # Granting WRITE on secret unlocks graph writes on the pair.
        self.user2.link_to_acl(secret, roles.Role.WRITER)
        self.assertEqual(
            client.patch(
                f"/api/v2/graph/{existing_rel.id}",
                json={"link_type": "edited", "description": "edited"},
                headers=headers,
            ).status_code,
            200,
        )
        self.assertEqual(
            client.delete(
                f"/api/v2/graph/{existing_rel.id}",
                headers=headers,
            ).status_code,
            200,
        )

    def test_role_none_hidden_from_search_and_graph(self):
        """A Role.NONE (0) ACL edge must not expose an object in search or
        graph traversal."""
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        self.user2.link_to_acl(self.group1, roles.Role.READER)
        self.group1.link_to_acl(self.entity1, roles.Role.NONE)
        self.user2.link_to_acl(self.entity2, roles.Role.NONE)

        headers = {"Authorization": f"Bearer {self.user2_token}"}
        # Direct GET is 403.
        self.assertEqual(
            client.get(
                f"/api/v2/entities/{self.entity1.id}", headers=headers
            ).status_code,
            403,
        )
        # Search and grouped search must exclude both Role.NONE objects.
        res = client.post(
            "/api/v2/entities/search",
            json={"query": {"name": "test"}},
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["entities"], [])

        grouped = client.post(
            "/api/v2/search/",
            json={"query": "test"},
            headers=headers,
        )
        self.assertEqual(grouped.status_code, 200)
        for section in grouped.json()["sections"]:
            self.assertEqual(section["results"], [])

        # Role.NONE on group membership must not inherit group's OWNER on object.
        self.user2.link_to_acl(self.group2, roles.Role.NONE)
        self.group2.link_to_acl(self.entity1, roles.Role.OWNER)
        self.assertEqual(
            client.get(
                f"/api/v2/entities/{self.entity1.id}", headers=headers
            ).status_code,
            403,
        )
        res = client.post(
            "/api/v2/entities/search",
            json={"query": {"name": "test1"}},
            headers=headers,
        )
        self.assertEqual(res.json()["entities"], [])

    def test_user_get_groups_under_rbac(self):
        """Non-admin users keep seeing their groups when RBAC is enabled."""
        self.user1.link_to_acl(self.group1, roles.Role.READER)
        self.assertEqual([g.name for g in self.user1.get_groups()], ["test1"])

        response = client.get(
            f"/api/v2/users/{self.user1.id}",
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual([g["name"] for g in data["groups"]], ["test1"])

    def test_duplicate_create_does_not_overwrite_restricted_objects(self):
        """Creating an entity, indicator, or observable with an existing key
        must not overwrite or take ownership of a restricted object, while
        callers with WRITE keep upsert behavior without resetting ACLs."""
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        ind = indicator.Regex(
            name="secret-regex",
            pattern="secret",
            diamond=indicator.DiamondModel.capability,
        ).save()
        self.user1.link_to_acl(ind, roles.Role.OWNER)
        obs = observable.Hostname(value="restricted.example.com").save()
        self.user1.link_to_acl(obs, roles.Role.OWNER)

        headers = {"Authorization": f"Bearer {self.user2_token}"}

        # Unauthorized entity create collision -> 403, content and ACL unchanged.
        res = client.post(
            "/api/v2/entities/",
            json={
                "entity": {
                    "name": "test1",
                    "type": "malware",
                    "description": "overwritten",
                }
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(entity.Malware.get(self.entity1.id).description, "")
        self.assertFalse(
            self.user2.has_permissions(self.entity1.extended_id, roles.Permission.READ)
        )

        # Authorized WRITER can still upsert without becoming OWNER.
        self.user2.link_to_acl(self.entity1, roles.Role.WRITER)
        res = client.post(
            "/api/v2/entities/",
            json={
                "entity": {
                    "name": "test1",
                    "type": "malware",
                    "description": "authorized-update",
                }
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(
            entity.Malware.get(self.entity1.id).description, "authorized-update"
        )
        self.assertFalse(
            self.user2.has_permissions(
                self.entity1.extended_id, roles.Permission.DELETE
            )
        )

        # Unauthorized indicator create collision -> 403, pattern and ACL unchanged.
        res = client.post(
            "/api/v2/indicators/",
            json={
                "indicator": {
                    "name": "secret-regex",
                    "type": "regex",
                    "pattern": "pwned",
                    "diamond": "capability",
                }
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(indicator.Regex.get(ind.id).pattern, "secret")
        self.assertFalse(
            self.user2.has_permissions(ind.extended_id, roles.Permission.READ)
        )

        # Authorized WRITER can still upsert indicator without becoming OWNER.
        self.user2.link_to_acl(ind, roles.Role.WRITER)
        res = client.post(
            "/api/v2/indicators/",
            json={
                "indicator": {
                    "name": "secret-regex",
                    "type": "regex",
                    "pattern": "updated",
                    "diamond": "capability",
                }
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(indicator.Regex.get(ind.id).pattern, "updated")
        self.assertFalse(
            self.user2.has_permissions(ind.extended_id, roles.Permission.DELETE)
        )

        # Observable bulk / import / add_text collision must not steal ACL or tag.
        res = client.post(
            "/api/v2/observables/bulk",
            json={
                "observables": [
                    {
                        "type": "hostname",
                        "value": "restricted.example.com",
                        "tags": ["pwned"],
                    }
                ]
            },
            headers=headers,
        )
        self.assertEqual(res.status_code, 400)
        res = client.post(
            "/api/v2/observables/import/text",
            json={"text": "restricted.example.com", "tags": ["pwned"]},
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["added"], [])
        self.assertIn("restricted.example.com", res.json()["failed"])
        res = client.post(
            "/api/v2/observables/add_text",
            json={"text": "restricted.example.com", "tags": ["pwned"]},
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)
        refreshed_obs = observable.Hostname.get(obs.id)
        self.assertEqual(refreshed_obs.tags, [])
        self.assertFalse(
            self.user2.has_permissions(obs.extended_id, roles.Permission.READ)
        )

    def test_delete_rbac_relationship_requires_owner(self):
        """A non-owner (including READER or WRITER) cannot delete another
        user's ACL relationship on a shared object."""
        owner_rel = self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        self.user2.link_to_acl(self.entity1, roles.Role.WRITER)

        res = client.delete(
            f"/api/v2/rbac/{owner_rel.id}",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 403)
        self.assertTrue(
            self.user1.has_permissions(self.entity1.extended_id, roles.Role.OWNER)
        )

        # Admin can still delete the relationship.
        res = client.delete(
            f"/api/v2/rbac/{owner_rel.id}",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(res.status_code, 200)

    def test_audit_timeline_requires_read_permission(self):
        """Audit timeline refuses callers without READ on the target object."""
        self.user1.link_to_acl(self.entity1, roles.Role.OWNER)
        audit.log_timeline(self.user1.username, self.entity1)

        res = client.get(
            f"/api/v2/audit/timeline/{self.entity1.extended_id}",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 403)

        for token in (self.user1_token, self.admin_token):
            res = client.get(
                f"/api/v2/audit/timeline/{self.entity1.extended_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()[1], 1)

    def test_templates_render_enforces_observable_acls(self):
        """Template rendering enforces READ on both search_query and observable_ids."""
        tmpl_dir = Path("/opt/yeti/templates")
        tmpl_dir.mkdir(parents=True, exist_ok=True)
        tmpl = template.Template(
            name="RbacTestTemplate",
            template="{% for obs in data %}{{ obs.value }}\n{% endfor %}",
        ).save()
        self.addCleanup(
            lambda: (tmpl_dir / f"{tmpl.name}.jinja2").unlink(missing_ok=True)
        )

        pub = observable.Hostname(value="public-rbac.example.com").save()
        sec = observable.Hostname(value="secret-rbac.example.com").save()
        self.user1.link_to_acl(pub, roles.Role.OWNER)
        self.user1.link_to_acl(sec, roles.Role.OWNER)
        self.user2.link_to_acl(pub, roles.Role.READER)

        headers = {"Authorization": f"Bearer {self.user2_token}"}
        res = client.post(
            "/api/v2/templates/render",
            json={"template_name": tmpl.name, "observable_ids": [sec.id]},
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)

        res = client.post(
            "/api/v2/templates/render",
            json={"template_name": tmpl.name, "search_query": "rbac.example.com"},
            headers=headers,
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn("public-rbac.example.com", res.text)
        self.assertNotIn("secret-rbac.example.com", res.text)

        res = client.post(
            "/api/v2/templates/render",
            json={"template_name": tmpl.name, "observable_ids": [sec.id]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn("secret-rbac.example.com", res.text)

    def test_yara_bundle_enforces_read_on_ids_and_dependencies(self):
        """YARA bundle checks READ on requested IDs and on resolved dependencies."""
        dep = indicator.Yara(
            name="RbacDepRule",
            pattern='rule RbacDepRule { strings: $a = "secret" condition: $a }',
            diamond=indicator.DiamondModel.capability,
        ).save()
        main_rule = indicator.Yara(
            name="RbacMainRule",
            pattern="rule RbacMainRule { condition: RbacDepRule }",
            diamond=indicator.DiamondModel.capability,
        ).save()
        self.user1.link_to_acl(dep, roles.Role.OWNER)
        self.user1.link_to_acl(main_rule, roles.Role.OWNER)

        headers = {"Authorization": f"Bearer {self.user2_token}"}
        # Unreadable rule by ID -> 403.
        res = client.post(
            "/api/v2/indicators/yara/bundle",
            json={"ids": [dep.id]},
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)

        # Readable main rule whose dependency is unreadable -> 403.
        self.user2.link_to_acl(main_rule, roles.Role.READER)
        res = client.post(
            "/api/v2/indicators/yara/bundle",
            json={"ids": [main_rule.id]},
            headers=headers,
        )
        self.assertEqual(res.status_code, 403)

        # Once dependency is also readable -> 200 with both rules.
        self.user2.link_to_acl(dep, roles.Role.READER)
        res = client.post(
            "/api/v2/indicators/yara/bundle",
            json={"ids": [main_rule.id]},
            headers=headers,
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn("RbacDepRule", res.json()["bundle"])
        self.assertIn("RbacMainRule", res.json()["bundle"])

    def test_graph_match_filters_regex_indicators_by_acl(self):
        """POST /api/v2/graph/match only returns regex indicators the caller can read."""
        regex = indicator.Regex(
            name="PrivateRegex",
            pattern=r"secret-token-\d+",
            diamond=indicator.DiamondModel.capability,
        ).save()
        self.user1.link_to_acl(regex, roles.Role.OWNER)

        res = client.post(
            "/api/v2/graph/match",
            json={"observables": ["secret-token-42"]},
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["matches"], [])

        res = client.post(
            "/api/v2/graph/match",
            json={"observables": ["secret-token-42"]},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(len(res.json()["matches"]), 1)
        self.assertEqual(res.json()["matches"][0][1]["name"], "PrivateRegex")

    @mock.patch(
        "core.web.apiv2.system.app.control.broadcast",
        return_value=[{"w1": {"ok": "reloading"}}],
    )
    @mock.patch("core.taskscheduler.run_task.delay")
    def test_tasks_run_toggle_and_restartworker_enforce_rbac(
        self, mock_delay, mock_broadcast
    ):
        """Task run requires global WRITE; task toggle and worker restart require admin."""
        task.FeedTask(
            name="RbacFeed",
            frequency=datetime.timedelta(hours=1),
            description="test",
        ).save()

        self.user2.global_role = roles.Role.READER
        self.user2.save()
        self.user1.global_role = roles.Role.WRITER
        self.user1.save()

        reader_h = {"Authorization": f"Bearer {self.user2_token}"}
        writer_h = {"Authorization": f"Bearer {self.user1_token}"}
        admin_h = {"Authorization": f"Bearer {self.admin_token}"}

        # /run: READER 403, WRITER 200.
        self.assertEqual(
            client.post("/api/v2/tasks/RbacFeed/run", headers=reader_h).status_code, 403
        )
        self.assertEqual(
            client.post("/api/v2/tasks/RbacFeed/run", headers=writer_h).status_code, 200
        )

        # /toggle: READER 403, WRITER 403, admin 200.
        self.assertEqual(
            client.post("/api/v2/tasks/RbacFeed/toggle", headers=reader_h).status_code,
            403,
        )
        self.assertEqual(
            client.post("/api/v2/tasks/RbacFeed/toggle", headers=writer_h).status_code,
            403,
        )
        self.assertEqual(
            client.post("/api/v2/tasks/RbacFeed/toggle", headers=admin_h).status_code,
            200,
        )

        # /restartworker: READER 403, WRITER 403, admin 200.
        self.assertEqual(
            client.post(
                "/api/v2/system/restartworker/all", headers=reader_h
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post(
                "/api/v2/system/restartworker/all", headers=writer_h
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post(
                "/api/v2/system/restartworker/all", headers=admin_h
            ).status_code,
            200,
        )

    def test_exports_enforce_owner_and_observable_acls(self):
        """Exports filter observables by owner's ACLs and restrict export
        management/download to the owner or an admin."""
        tmpl_dir = Path("/opt/yeti/templates")
        tmpl_dir.mkdir(parents=True, exist_ok=True)
        tmpl = template.Template(
            name="RbacExportTemplate",
            template="{% for obs in data %}{{ obs.value }}\n{% endfor %}",
        ).save()
        self.addCleanup(
            lambda: (tmpl_dir / f"{tmpl.name}.jinja2").unlink(missing_ok=True)
        )

        secret_obs = observable.save(value="export-secret.example.com", tags=["ir042"])
        shared_obs = observable.save(value="export-shared.example.com", tags=["ir042"])
        self.user1.link_to_acl(secret_obs, roles.Role.OWNER)
        self.user1.link_to_acl(shared_obs, roles.Role.OWNER)
        self.user2.link_to_acl(shared_obs, roles.Role.READER)

        self.user2.global_role = roles.Role.READER
        self.user2.save()
        res = client.post(
            "/api/v2/tasks/export/new",
            json={
                "export": {
                    "name": "User2Export",
                    "acts_on": ["hostname"],
                    "include_tags": ["ir042"],
                    "template_name": tmpl.name,
                }
            },
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 403)

        # WRITER creates export; attempted owner spoofing is overwritten server-side.
        self.user2.global_role = roles.Role.WRITER
        self.user2.save()
        res = client.post(
            "/api/v2/tasks/export/new",
            json={
                "export": {
                    "name": "User2Export",
                    "acts_on": ["hostname"],
                    "include_tags": ["ir042"],
                    "template_name": tmpl.name,
                    "owner": "yeti",
                }
            },
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        export_id = res.json()["id"]
        self.assertEqual(res.json()["owner"], "user2")

        # Running the export only outputs observables readable by user2.
        export_task = task.ExportTask.get(export_id)
        export_task.run()
        res = client.get(
            f"/api/v2/tasks/export/{export_id}/content",
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("export-shared.example.com", res.text)
        self.assertNotIn("export-secret.example.com", res.text)

        # Another non-admin user cannot download, patch, run, or delete user2's export.
        user1_h = {"Authorization": f"Bearer {self.user1_token}"}
        self.assertEqual(
            client.get(
                f"/api/v2/tasks/export/{export_id}/content", headers=user1_h
            ).status_code,
            403,
        )
        self.assertEqual(
            client.patch(
                "/api/v2/tasks/export/User2Export",
                json={
                    "export": {
                        "name": "User2Export",
                        "template_name": tmpl.name,
                        "owner": "yeti",
                    }
                },
                headers=user1_h,
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post("/api/v2/tasks/User2Export/run", headers=user1_h).status_code,
            403,
        )
        self.assertEqual(
            client.delete(
                "/api/v2/tasks/export/User2Export", headers=user1_h
            ).status_code,
            403,
        )

        # Owner patching cannot spoof owner either; owner can delete.
        res = client.patch(
            "/api/v2/tasks/export/User2Export",
            json={
                "export": {
                    "name": "User2Export",
                    "template_name": tmpl.name,
                    "owner": "yeti",
                }
            },
            headers={"Authorization": f"Bearer {self.user2_token}"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["owner"], "user2")
        self.assertEqual(
            client.delete(
                "/api/v2/tasks/export/User2Export",
                headers={"Authorization": f"Bearer {self.user2_token}"},
            ).status_code,
            200,
        )
