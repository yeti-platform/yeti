from enum import IntFlag


class Permission(IntFlag):
    READ = 0b0001  # 1
    WRITE = 0b0010  # 2
    DELETE = 0b0100  # 4


class Role:
    NONE = Permission(0)
    READER = Permission.READ
    WRITER = Permission.READ | Permission.WRITE
    OWNER = Permission.READ | Permission.WRITE | Permission.DELETE
