import datetime
import json
import logging
import os
import queue
from logging import Formatter
from logging.handlers import QueueHandler, QueueListener

from core.config.config import yeti_config
from core.schemas.audit import AuditLog

# Inspired by
# * https://www.sheshbabu.com/posts/fastapi-structured-json-logging/
# * https://rob-blackbourn.medium.com/how-to-use-python-logging-queuehandler-with-dictconfig-1e8b1284e27a


class ArangoHandler(logging.Handler):
    actions = {
        "GET": "read",
        "POST": "create",
        "PATCH": "update",
        "DELETE": "delete",
    }

    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        if "type" not in record.__dict__:
            return
        if record.__dict__["type"] != "audit.log":
            return
        target = record.__dict__["path"]
        if "/auth/" in target or target.endswith("/search"):
            return
        action = self.actions.get(record.__dict__["method"], "unknown")
        if record.__dict__["status_code"] == 200:
            status = "succeeded"
        else:
            status = "failed"

        if "body" in record.__dict__ and record.__dict__["body"]:
            try:
                content = record.__dict__["body"]
                if isinstance(content, bytes):
                    content = content.decode("utf-8")
                content = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                # We don't want to log binary or non-JSON content.
                content = {}
        else:
            content = {}
        AuditLog(
            timestamp=datetime.datetime.fromtimestamp(record.created),
            username=record.__dict__["username"],
            action=action,
            status=status,
            target=target,
            content=content,
            status_code=record.__dict__["status_code"],
            ip=record.__dict__["client"],
        ).save()


class JsonFormatter(Formatter):
    def __init__(self):
        super(JsonFormatter, self).__init__()

    def format(self, record):
        json_record = {}
        json_record["message"] = record.getMessage()
        if "username" in record.__dict__:
            json_record["username"] = record.__dict__["username"]
        if "path" in record.__dict__:
            json_record["path"] = record.__dict__["path"]
        if "method" in record.__dict__:
            json_record["method"] = record.__dict__["method"]
        if "body" in record.__dict__ and record.__dict__["body"]:
            if record.__dict__["content-type"] == "application/json":
                json_record["body"] = json.loads(
                    record.__dict__["body"].decode("utf-8")
                )
            else:
                json_record["body"] = record.__dict__["body"].decode("utf-8")
        if "client" in record.__dict__:
            json_record["client"] = record.__dict__["client"]
        if "status_code" in record.__dict__:
            json_record["status_code"] = record.__dict__["status_code"]
        if record.levelno == logging.ERROR and record.exc_info:
            json_record["err"] = self.formatException(record.exc_info)
        return json.dumps(json_record)


class LogFilter(logging.Filter):
    no_log_endpoints = {
        "/api/v2/system/config",
        "/api/v2/bloom/search",
        "/api/v2/bloom/search/raw",
    }

    sensitive_endpoint_prefixes = (
        "/api/v2/auth",
        "/api/v2/users",
    )

    sensitive_field_substrings = ("password",)

    def filter_on_path(self, record) -> bool:
        if hasattr(record, "path") and record.path in self.no_log_endpoints:
            return False
        return True

    def redact_sensitive_fields(self, record):
        if hasattr(record, "path") and hasattr(record, "body"):
            if record.path.startswith(self.sensitive_endpoint_prefixes):
                try:
                    json_body = json.loads(record.body)
                    for sensitive_field in self.sensitive_field_substrings:
                        for key in json_body:
                            if sensitive_field in key:
                                json_body[key] = "REDACTED"
                    record.body = json.dumps(json_body)
                except Exception:
                    pass
        return

    def filter(self, record):
        if not self.filter_on_path(record):
            return False

        self.redact_sensitive_fields(record)

        return True


# Base logging config
logger = logging.getLogger("yeti.audit.log")
logger.setLevel(logging.INFO)
logger.propagate = False

# Queue handler
log_queue = queue.Queue(-1)
queue_handler = QueueHandler(log_queue)
logger.addHandler(queue_handler)
handlers = list()

# Console handler
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(username)s - %(path)s - %(method)s - %(body)s - %(client)s - %(status_code)s"

console_handler = logging.StreamHandler()
console_handler.addFilter(LogFilter())
console_handler.setFormatter(logging.Formatter(log_format))
handlers.append(console_handler)

audit_logfile = yeti_config.get("system", "audit_logfile")

if audit_logfile:
    if os.access(audit_logfile, os.W_OK):
        file_handler = logging.FileHandler(audit_logfile)
        file_handler.addFilter(LogFilter())
        file_handler.setFormatter(JsonFormatter())
        handlers.append(file_handler)
    else:
        logging.getLogger().warning("Audit log file not writable, using console only")
else:
    logging.getLogger().warning("Audit log file not configured, using console only")


# Arango Handler
arango_handler = ArangoHandler()
arango_handler.addFilter(LogFilter())
handlers.append(arango_handler)

# Listen for Logs
listener = QueueListener(log_queue, *handlers)
listener.start()
