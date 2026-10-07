from enum import IntEnum, IntFlag


class Permission(IntFlag):
    READ = 0b0001  # 1
    WRITE = 0b0010  # 2
    DELETE = 0b0100  # 4


class Role(IntEnum):
    """The Permission combinations actually granted over the API.

    A plain int/enum (not Permission itself) so FastAPI's OpenAPI generation
    -- and hence generated client types -- list exactly these four values
    instead of Permission's individual flags (1, 2, 4), which don't include
    the composite values (0, 3, 7) every role-granting endpoint actually
    accepts.
    """

    NONE = 0
    READER = Permission.READ
    WRITER = Permission.READ | Permission.WRITE
    OWNER = Permission.READ | Permission.WRITE | Permission.DELETE
