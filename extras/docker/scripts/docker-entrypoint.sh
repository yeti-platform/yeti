#!/bin/bash
set -euo pipefail

if [ "$1" = 'webserver' ]; then
    poetry run uvicorn core.web.webapp:app --reload --host 0.0.0.0
elif  [ "$1" = 'tasks' ]; then
    poetry run celery -A core.taskmanager worker --loglevel=INFO --purge -B -P threads
elif [ "$1" = 'createuser']; then
    poetry run yetictl createuser "${@:2}"
elif [ "$1" = 'resetpassword']; then
    poetry run yetictl resetpassword "${@:2}"
elif  [ "$1" = 'envshell' ]; then
    poetry shell
else
    exec "$@"
