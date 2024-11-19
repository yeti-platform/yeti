import re
from typing import Literal

from pydantic import field_validator

from core.schemas import observable

# Regex generated with https://chatgpt.com/share/6720b845-1cb8-8006-9005-1837e2654525

LINUX_PATH_REGEX = re.compile(
    r"""
^
(
    # Absolute path (e.g., /usr/local/bin/file)
    /(?:[^/\0]+/)+[^/\0]* |
    
    # Home directory path (e.g., ~/Documents/file)
    ~(?:/[^/\0]+)+ |
    
    # Relative path (e.g., bin/file or ../folder/file)
    (?:\./|\.\./|[^/\0]+/)+[^/\0]*
)
$
""",
    re.VERBOSE,
)

WINDOWS_PATH_REGEX = re.compile(
    r"""
^
(
    # Drive letter path (e.g., C:\path\to\file)
    [a-zA-Z]:[\\/](?:[^<>:"|?*\\/\r\n]+[\\/])+[^<>:"|?*\\/\r\n]* |
    
    # UNC path (e.g., \\server\share\path\to\file)
    \\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9$_.-]+(?:\\[^<>:"|?*\\/\r\n]+)+ |
    
    # Relative path (e.g., folder\file or ..\folder\file)
    (?:\.\.?(?:[\\/]|$))+[\\/](?:[^<>:"|?*\\/\r\n]+[\\/])+[^<>:"|?*\\/\r\n]*
)
$
""",
    re.VERBOSE,
)


class Path(observable.Observable):
    type: Literal["path"] = "path"

    @classmethod
    def validator(cls, value: str) -> bool:
        if LINUX_PATH_REGEX.match(value) or WINDOWS_PATH_REGEX.match(value):
            return True
        else:
            return False
