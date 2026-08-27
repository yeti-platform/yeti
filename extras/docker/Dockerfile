# Actual Yeti container
#
# -slim rather than the full python image: the latter descends from
# buildpack-deps, which drags in development headers for software Yeti does not
# use -- libpq among them, so every PostgreSQL advisory shows up in scans of an
# image that has no PostgreSQL server and talks to ArangoDB.
FROM python:3.13-slim AS yeti

# gcc and libc6-dev build yara-python, which publishes no wheel for this
# platform. They used to arrive by accident: the python3-pip package pulled a
# compiler in as a dependency, so removing it broke the build in a way that
# had nothing to do with pip. The image's own pip is what actually gets used.
#
# git is here because one dependency is a git+https URL and uv needs it to
# resolve.
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    git \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ADD . /app

WORKDIR /app
RUN cp yeti.conf.sample yeti.conf
RUN cp ./extras/docker/docker-entrypoint.sh /docker-entrypoint.sh

# Upgrade pip
RUN pip3 install --upgrade pip && pip3 install uv

# Install yeti
RUN uv sync --group plugins

ENV PYTHONPATH /app

ENTRYPOINT ["/docker-entrypoint.sh"]
