# Docker support

This is probably the quickest way to get started with Yeti.

## Install docker

Follow the [official instructions](https://www.docker.com/community-edition).

## Clone the repo

    $ git clone https://github.com/yeti-platform/yeti
    $ cd yeti

## Start containers

    $ docker-compose -f extras/docker/docker-compose.yml up

You can also invoke docker-compose from the `docker` directory

    $ cd extras/docker
    $ docker-compose up

## Have fun!

The `docker-compose up` command should start a working Yeti container listening
for connections on `http://localhost:5000/`.
