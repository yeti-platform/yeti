from typing import ClassVar, Literal

from core.schemas import entity


class CourseOfAction(entity.Entity):
    _type_filter: ClassVar[str] = "course-of-action"
    type: Literal["course-of-action"] = "course-of-action"
