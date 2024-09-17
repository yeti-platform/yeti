from typing import ClassVar

from core.schemas import entity


class CourseOfAction(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.course_of_action
    type: entity.EntityType = entity.EntityType.course_of_action
