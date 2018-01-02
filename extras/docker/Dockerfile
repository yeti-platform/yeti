FROM ubuntu:16.04

RUN apt-get update && apt-get dist-upgrade -y && apt-get autoremove -y && apt-get clean && apt-get install -y \
  build-essential \
  python-dev \
  libxml2-dev \
  libxslt-dev \
  zlib1g-dev \
  python-virtualenv \
  python-pip \
  git \
  locales

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

ADD . /opt/yeti
WORKDIR /opt/yeti
RUN pip install -r requirements.txt

RUN mv yeti.conf.sample yeti.conf
RUN sed -i '9s/# host = 127.0.0.1/host = mongodb/' yeti.conf
RUN sed -i '22s/# host = 127.0.0.1/host = redis/' yeti.conf

EXPOSE 5000

CMD ["./yeti.py", "webserver"]
