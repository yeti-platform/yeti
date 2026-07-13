from core.events import message
from core.schemas import (  # noqa: F401  (imported for their side-effect registration)
    dfiq,
    entity,
    graph,
    indicator,
    observable,
    rbac,
    tag,
    task,
    template,
    user,
)

# Importing the schema modules above triggers their static type registration
# (see the "Static type registry" sections in observable.py / entity.py /
# indicator.py; dfiq.py registers its own types inline). Rebuild the event
# message model now that every referenced schema type is importable.
message.EventMessage.model_rebuild()
