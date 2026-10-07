import unittest

from core.schemas import roles


class RoleTest(unittest.TestCase):
    def test_role_has_exactly_the_meaningful_composite_values(self) -> None:
        """Role must stay exactly {NONE, READER, WRITER, OWNER} = {0, 1, 3, 7}.

        This is the enum FastAPI/OpenAPI generation exposes as the accepted
        `role` values on every role-granting endpoint -- adding, removing, or
        renumbering a member here directly changes the public API contract.
        """
        self.assertEqual(
            {member.name: member.value for member in roles.Role},
            {"NONE": 0, "READER": 1, "WRITER": 3, "OWNER": 7},
        )

    def test_role_values_match_permission_flag_combinations(self) -> None:
        self.assertEqual(roles.Role.NONE, 0)
        self.assertEqual(roles.Role.READER, roles.Permission.READ)
        self.assertEqual(
            roles.Role.WRITER, roles.Permission.READ | roles.Permission.WRITE
        )
        self.assertEqual(
            roles.Role.OWNER,
            roles.Permission.READ | roles.Permission.WRITE | roles.Permission.DELETE,
        )

    def test_role_is_a_real_int_enum_not_the_permission_flag(self) -> None:
        """Role must NOT be Permission (or a Permission subclass/alias).

        Sharing Permission's type is exactly the bug this enum exists to
        avoid: OpenAPI would only list Permission's individually-declared
        flags (1, 2, 4), not the composite values (0, 3, 7) actually
        accepted.
        """
        self.assertFalse(issubclass(roles.Role, roles.Permission))
        self.assertNotIsInstance(roles.Role.OWNER, roles.Permission)
