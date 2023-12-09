#!/bin/bash
set -euo pipefail

if [[ "$1" = 'webserver' ]]; then
    poetry run uvicorn core.web.webapp:app --reload --host 0.0.0.0
elif [[ "$1" = 'tasks' ]]; then
    poetry run celery -A core.taskscheduler worker --loglevel=INFO --purge -B -P threads
elif [[ "$1" = 'create-user' ]]; then
    poetry run python yetictl/cli.py create-user "${@:2}"
elif [[ "$1" = 'reset-password' ]]; then
    poetry run python yetictl/cli.py reset-password "${@:2}"
elif [[ "$1" = 'toggle-user' ]]; then
    poetry run python yetictl/cli.py toggle-user "${@:2}"
elif [[ "$1" = 'toggle-admin' ]]; then
    poetry run python yetictl/cli.py toggle-admin "${@:2}"
elif [[ "$1" = 'envshell' ]]; then
    poetry shell
else
    exec "$@"
fi
