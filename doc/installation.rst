.. _installation:

Installation
============

Yeti has a `docker-compose` script to get up and running even faster; this is useful for testing or even running production instances of Yeti should your infrastructure support it. Full instructions [here](https://github.com/yeti-platform/yeti/tree/master/extras/docker), but in a nutshell:

Download in release page the lastest version of yeti <https://github.com/yeti-platform/yeti/releases>

To install docker and docker-compose follow the instructions on the official documentation <https://docs.docker.com/compose/install/>

```bash
    gunzip yeti-<version>.zip
    cd yeti/extras/docker/dev
    docker-compose up
```

The docker-compose will start the following containers
