from typing import ClassVar, Literal

from core.schemas import entity


class Tool(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.tool
    type: Literal[entity.EntityType.tool] = entity.EntityType.tool

    aliases: list[str] = []
    kill_chain_phases: list[str] = []
    tool_version: str = ""
