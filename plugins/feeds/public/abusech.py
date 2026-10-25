"""Downloads from abuse.ch's authenticated exports.

abuse.ch serves MalwareBazaar, ThreatFox and URLhaus exports only with an
Auth-Key, free from https://auth.abuse.ch/, and only in the URL path. Set it as
``auth_key`` in the ``[abusech]`` section of yeti.conf, or as
``YETI_ABUSECH_AUTH_KEY``.
"""

import requests

from core.config.config import yeti_config
from core.schemas import task

REDACTED = "<abuse.ch auth key>"


def auth_key() -> str | None:
    return yeti_config.get("abusech", "auth_key") or None


def fetch_export(
    feed: task.FeedTask, source: str, **kwargs
) -> requests.Response | None:
    """Fetches ``source``, an export URL with an ``{auth_key}`` placeholder.

    Errors are re-raised with the key masked: the URL is in their message,
    which ends up in logs and in the task's status message.
    """
    key = auth_key()
    if not key:
        raise RuntimeError(
            f"{feed.name} needs an abuse.ch Auth-Key: set auth_key in the "
            "[abusech] section of yeti.conf, or YETI_ABUSECH_AUTH_KEY"
        )
    try:
        return feed._make_request(source.format(auth_key=key), **kwargs)
    except Exception as error:
        message = str(error).replace(key, REDACTED)
        # from None, so the traceback doesn't print the unmasked original.
        raise RuntimeError(message) from None
