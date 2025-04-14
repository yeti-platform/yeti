#!/bin/bash
set -euo pipefail

if [[ "$1" = 'webserver' ]]; then
    uv run uvicorn core.web.webapp:app --reload --host 0.0.0.0 --log-level=debug
elif [[ "$1" = 'webserver-prod' ]]; then
    uv run uvicorn core.web.webapp:app --host 0.0.0.0 --workers $(nproc --all || echo 4) --log-level=info
elif [[ "$1" = 'tasks' ]]; then
    uv run celery -A core.taskscheduler worker --loglevel=INFO --purge -P threads
elif [[ "$1" = 'tasks-beat' ]]; then
    rm -f celerybeat-schedule.db && uv run celery -A core.taskscheduler beat
elif [[ "$1" = 'events-tasks' ]]; then
    uv run python -m core.events.consumers events
elif [[ "$1" = 'create-user' ]]; then
    uv run python yetictl/cli.py create-user "${@:2}"
elif [[ "$1" = 'reset-password' ]]; then
    uv run python yetictl/cli.py reset-password "${@:2}"
elif [[ "$1" = 'toggle-user' ]]; then
    uv run python yetictl/cli.py toggle-user "${@:2}"
elif [[ "$1" = 'toggle-admin' ]]; then
    uv run python yetictl/cli.py toggle-admin "${@:2}"
elif [[ "$1" = 'migrate-arangodb' ]]; then
    uv run python yetictl/cli.py migrate-arangodb "${@:2}"
elif [[ "$1" = 'envshell' ]]; then
    $(uv env activate) && exec bash
else
    exec "$@"
fi
