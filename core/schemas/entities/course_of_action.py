from typing import ClassVar, Literal

from core.schemas import entity


class CourseOfAction(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.course_of_action
    type: Literal[entity.EntityType.course_of_action] = (
        entity.EntityType.course_of_action
    )
