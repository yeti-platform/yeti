from typing import ClassVar, Literal

from core.schemas import entity


class Tool(entity.Entity):
    _type_filter: ClassVar[str] = "tool"
    type: Literal["tool"] = "tool"

    aliases: list[str] = []
    kill_chain_phases: list[str] = []
    tool_version: str = ""
