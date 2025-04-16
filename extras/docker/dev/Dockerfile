FROM ubuntu:22.04

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

# Python
RUN apt-get update && apt-get install -y \
    python3-pip \
    libmagic-dev \
    git

# Upgrade pip
RUN pip3 install --upgrade pip && pip3 install uv

# Install & Configure YETI
ADD . /app
WORKDIR /app
RUN uv sync --all-groups

COPY --chmod=744 ./extras/docker/docker-entrypoint.sh /docker-entrypoint.sh

ENV PYTHONPATH /app

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["webserver"]
