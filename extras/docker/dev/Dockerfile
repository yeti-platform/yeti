FROM ubuntu:18.04

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

# Python
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3-pip \
    python-yara \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
    # ftontend

# Install frontend dependencies
RUN apt-get update && apt-get install -y --no-install-suggests --no-install-recommends \
        gnupg2 && \
        curl -sL https://deb.nodesource.com/setup_14.x |  bash - && \
        curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && \
        echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list && \
        apt-get update && apt-get install -y \
        nodejs \
        yarn \
        && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/* /usr/share/man/* /root/.cache/*


# Upgrade pip
RUN pip3 install --upgrade pip

# Install & Configure YETI
ADD . /opt/yeti
WORKDIR /opt/yeti
RUN pip3 install -r requirements.txt && \
        yarn install && \
        mv yeti.conf.sample yeti.conf && \
        sed -i '25s/# host = 127.0.0.1/host = mongodb/' yeti.conf && \
        sed -i '38s/# host = 127.0.0.1/host = redis/' yeti.conf

RUN mkdir /var/log/yeti

# Update tld domain list
RUN tldextract --update

COPY ./extras/docker/scripts/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["webserver"]
