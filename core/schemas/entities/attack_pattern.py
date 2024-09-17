from typing import ClassVar

from core.schemas import entity


class AttackPattern(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.attack_pattern
    type: entity.EntityType = entity.EntityType.attack_pattern
    aliases: list[str] = []
    kill_chain_phases: list[str] = []
