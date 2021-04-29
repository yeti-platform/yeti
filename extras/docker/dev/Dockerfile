FROM ubuntu:20.04

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

# Python
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
    # ftontend

# Upgrade pip
RUN pip3 install --upgrade pip && pip3 install pipenv

# Install & Configure YETI
ADD . /opt/yeti
WORKDIR /opt/yeti
RUN pipenv install --system && \
        mv yeti.conf.sample yeti.conf && \
        sed -i '25s/# host = 127.0.0.1/host = mongodb/' yeti.conf && \
        sed -i '38s/# host = 127.0.0.1/host = redis/' yeti.conf

RUN mkdir /var/log/yeti

# Update tld domain list
RUN tldextract --update

COPY ./extras/docker/scripts/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["webserver"]
