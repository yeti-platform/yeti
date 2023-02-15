FROM ubuntu:22.04

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

# Python
RUN apt-get update && apt-get install -y \
    python3-pip \
    libmagic-dev

# Upgrade pip
RUN pip3 install --upgrade pip && pip3 install poetry

# Install & Configure YETI
ADD . /app
WORKDIR /app
RUN poetry install && \
        mv yeti.conf.sample yeti.conf && \
        sed -i '35s/# host = 127.0.0.1/host = mongodb/' yeti.conf && \
        sed -i '49s/# host = 127.0.0.1/host = redis/' yeti.conf

RUN mkdir /var/log/yeti

# Update tld domain list
RUN poetry run tldextract --update

COPY ./docker/scripts/docker-entrypoint.sh /docker-entrypoint.sh

ENV PYTHONPATH /app

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["webserver"]
