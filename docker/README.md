# Docker support

This is probably the quickest way to get started with Yeti.

## Install `docker` and `docker-compose`

Follow the [official instructions](https://www.docker.com/community-edition).

## Clone the repo

    git clone https://github.com/yeti-platform/yeti
    cd yeti

## Start Yeti

The following command will build a Docker image named `yeti-platform` and launch it :

    docker-compose -p yeti -f extras/docker/dev/docker-compose.yaml up -d

You can also invoke docker-compose from the `docker` directory

    cd extras/docker/dev
    docker-compose up

The `docker-compose` command should build the master Yeti Docker image and start
6 docker containers, one for each service:

* `yeti` (the main webserver / API)
* `feeds` (for running feeds Celery tasks)
* `analytics` (for running the analytics Celery tasks)
* `beat` (for scheduling the Celery tasks)
* `exports` (for running the exports Celery tasks)
* `oneshot` (for running the oneshot Celery tasks)

And two more:

* `redis` (the redis server)
* `mongodb` (the mongodb server)

This will start a Yeti service running on <http://localhost:5000/>

### Prod setup

To start a more performant container for web requests, run:

    docker-compose -p yeti -f extras/docker/dev/docker-compose.yaml run -p 8080:8080 yeti /docker-entrypoint.sh uwsgi-http

Then point your browser to <http://localhost:8080.>
