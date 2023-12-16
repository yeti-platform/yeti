from pydantic import BaseModel, computed_field


class YetiModel(BaseModel):
   __id: str | None = None

   def __init__(self, **data):
      super().__init__(**data)
      self.__id = data.get("__id", None)

   @computed_field(return_type=str)
   @property
   def id(self):
      return self.__id
