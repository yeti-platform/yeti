# Actual Yeti container
FROM python:3.10 AS yeti

# Python
RUN apt-get update && apt-get install -y \
    python3-pip \
    libmagic-dev \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ADD . /app

WORKDIR /app
RUN cp yeti.conf.sample yeti.conf
RUN cp ./extras/docker/docker-entrypoint.sh /docker-entrypoint.sh

# Upgrade pip
RUN pip3 install --upgrade pip && pip3 install poetry

# Install yeti
RUN poetry install --no-root --with plugins

ENV PYTHONPATH /app

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["webserver"]
