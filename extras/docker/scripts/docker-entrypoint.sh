#!/bin/bash
set -euo pipefail

if [ "$1" = 'webserver' ]; then
    poetry run uvicorn core.web.webapp:app --reload --host 0.0.0.0
elif  [ "$1" = 'tasks' ]; then
    poetry run celery -A core.taskmanager worker --loglevel=INFO -Ofair --autoscale=10,2 --purge -Q analytics -n analytics
elif  [ "$1" = 'envshell' ]; then
    poetry shell
fi

exec "$@"
