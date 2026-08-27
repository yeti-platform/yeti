# Actual Yeti container
#
# -slim avoids buildpack-deps, whose development headers (libpq among them) are
# unused by Yeti and only add size and scan surface.
FROM python:3.13-slim AS yeti

# gcc and libc6-dev are required to compile yara-python, which publishes no
# wheel for this platform. git is required to resolve a dependency pinned to a
# git+https URL.
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
