# Docker support

This is probably the quickest way to get started with Yeti.

## Install docker

Follow the [official instructions](https://www.docker.com/community-edition).

## Clone the repo

    $ git clone https://github.com/yeti-platform/yeti
    $ cd yeti

## Start Yeti
The following command will build a Docker image named `yeti-platform` and launch it :

    $ docker-compose -f extras/docker/docker-compose.yml up

You can also invoke docker-compose from the `docker` directory

    $ cd extras/docker
    $ docker-compose up

The `docker-compose up` command should start a working Yeti container listening
for connections on `http://localhost:5000/`. No other services will be available  (e.g. feeds), just the web interface.

Alternatively you can launch a fully featured Yeti instance by executing:

    $ docker-compose -f docker-compose-full.yml up

The above will launch Yeti with uWSGI over an HTTP socket along with all of its services. Yeti will be available under `http://localhost:8080`.

## Notes

1. A custom configuration file can be mounted under Yeti's image by editing the
compose file and using the `volumes` option. For example:
```
version: '3'
services:
  yeti:
    build:
      context: ../../
      dockerfile: ./extras/docker/Dockerfile
    ports:
      - "5000:5000"
    links:
      - redis
      - mongodb
    volumes:
      - /my/custom/yeti/config:/opt/yeti/yeti.conf:ro
    restart: always
```
2. Keep in mind, database data do __not__ persist after container destruction. If you require
persistence for your data, you can use the `volumes` option on the `mongodb` service  and mount an appropriate volume for your data.  For more information you can check the relevant [official documentation](https://docs.docker.com/storage/volumes/).
3. If you want to launch the image in native uWSGI socket mode for use `uwsgi`, instead of `uwsgi-http`, as an argument for the `docker-entrypoint.sh` script.
