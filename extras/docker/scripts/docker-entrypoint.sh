#!/bin/bash
set -euo pipefail

if [ "$1" = 'webserver' ]; then
    poetry run ./yeti.py webserver --debug
elif  [ "$1" = 'uwsgi' ]; then
    poetry add uwsgi && poetry run /usr/local/bin/uwsgi --socket 0.0.0.0:8080 -w yeti --callable webapp --processes 4 --stats 0.0.0.0:9191 --max-requests 100 --lazy-apps
elif  [ "$1" = 'uwsgi-http' ]; then
    poetry add uwsgi && poetry run /usr/local/bin/uwsgi --http 0.0.0.0:8080 -w yeti --callable webapp --processes 4 --stats 0.0.0.0:9191 --stats-http --max-requests 100 --lazy-apps
elif  [ "$1" = 'analytics' ]; then
    poetry run /usr/local/bin/celery -A core.config.celeryctl.celery_app worker -Ofair --autoscale=10,2 --purge -Q analytics -n analytics
elif  [ "$1" = 'beat' ]; then
    poetry run /usr/local/bin/celery -A core.config.celeryctl beat -S core.scheduling.Scheduler
elif  [ "$1" = 'exports' ]; then
    poetry run /usr/local/bin/celery -A core.config.celeryctl.celery_app worker -Ofair --autoscale=10,2 -Q exports -n exports --purge
elif  [ "$1" = 'feeds' ]; then
    poetry run /usr/local/bin/celery -A core.config.celeryctl.celery_app worker -Ofair --autoscale=10,2 -Q feeds -n feeds --purge
elif  [ "$1" = 'oneshot' ]; then
    poetry run /usr/local/bin/celery -A core.config.celeryctl.celery_app worker --autoscale=4,2 -Q oneshot -n oneshot --purge
elif  [ "$1" = 'envshell' ]; then
    poetry shell
fi

exec "$@"
