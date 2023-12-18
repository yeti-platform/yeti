from core.schemas.graph import TagRelationship
from pydantic import BaseModel, computed_field


class YetiModel(BaseModel):
   __id: str | None = None

   def __init__(self, **data):
      print("MODEL ---->", data)
      super().__init__(**data)
      self.__id = data.get("__id", None)

   @computed_field(return_type=str)
   @property
   def id(self):
      return self.__id
   
class YetiTagModel(YetiModel):

   _tags: dict[str, TagRelationship] = {}

   def __init__(self, **data):
      print("TAGMODEL ---->", data)
      super().__init__(**data)
      self._tags = data.get("_tags", {})


   @computed_field(return_type=dict[str, TagRelationship])
   @property
   def tags(self):
      return self._tags

