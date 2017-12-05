FROM ubuntu:16.04

RUN apt-get update && apt-get dist-upgrade -y && apt-get autoremove -y && apt-get clean && apt-get install -y \
  build-essential\
  git \
  python-dev \
  mongodb \
  redis-server \
  libxml2-dev \
  libxslt-dev \
  zlib1g-dev \
  python-virtualenv \
  python-pip \
  nginx \
  locales \
  wget \
  unzip

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

RUN wget https://github.com/yeti-platform/yeti/archive/master.zip && \
  unzip master.zip && \
  pip install -r yeti-master/requirements.txt

WORKDIR yeti-master

RUN mongod --fork --config /etc/mongodb.conf
EXPOSE 5000

CMD ["./yeti.py", "webserver"]
