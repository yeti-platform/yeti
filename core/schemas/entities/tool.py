from typing import ClassVar

from core.schemas import entity


class Tool(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.tool
    type: entity.EntityType = entity.EntityType.tool

    aliases: list[str] = []
    kill_chain_phases: list[str] = []
    tool_version: str = ""
