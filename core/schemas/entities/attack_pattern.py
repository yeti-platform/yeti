from typing import ClassVar, Literal

from core.schemas import entity


class AttackPattern(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.attack_pattern
    type: Literal[entity.EntityType.attack_pattern] = entity.EntityType.attack_pattern
    aliases: list[str] = []
    kill_chain_phases: list[str] = []
