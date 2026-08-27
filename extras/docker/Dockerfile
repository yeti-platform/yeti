# Actual Yeti container
#
# -slim rather than the full python image: the latter descends from
# buildpack-deps, which drags in development headers for software Yeti does not
# use -- libpq among them, so every PostgreSQL advisory shows up in scans of an
# image that has no PostgreSQL server and talks to ArangoDB. Slim carries 223
# packages instead of 487. git is needed because a dependency is a git+https
# URL; no compiler is required, every C extension resolves to a wheel.
FROM python:3.13-slim AS yeti

# Python
RUN apt-get update && apt-get install -y \
    python3-pip \
    libmagic-dev \
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
