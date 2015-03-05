FROM ubuntu:14.04
MAINTAINER Thomas Chopitea <tomchop@gmail.com>

# update and install dependencies
RUN apt-get -qq update && apt-get -qqy install build-essential git python-dev libevent-dev mongodb libxml2-dev libxslt-dev zlib1g-dev redis-server libffi-dev libssl-dev python-pip

VOLUME ['/var/lib/mongodb']
# scapy
ADD http://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz /opt/scapy-latest.tar.gz
RUN cd /opt && \
	tar xzf scapy-latest.tar.gz && \
	rm scapy-latest.tar.gz && \
	mv scapy* scapy && \
	cd scapy && \
	python setup.py install

# get malcom
RUN cd /opt && \
	git clone https://github.com/tomchop/malcom.git malcom

# get maxmind geoip database
ADD http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz /opt/malcom/Malcom/auxiliary/geoIP/GeoLite2-City.mmdb.gz
RUN cd /opt/malcom/Malcom/auxiliary/geoIP && \
	gunzip -d GeoLite2-City.mmdb.gz && \
	mv GeoLite2-City.mmdb GeoIP2-City.mmdb

# set working dir, install python modules and launch webserver
WORKDIR /opt/malcom
RUN pip install -r requirements.txt
RUN cp malcom.conf.example malcom.conf
RUN sed -i s/scheduler\ =\ false/scheduler\ =\ true/g malcom.conf
EXPOSE 8080
RUN echo service mongodb start > start.sh
RUN echo service redis-server start >> start.sh
RUN echo ./malcom.py -c malcom.conf >> start.sh
RUN chmod +x start.sh
CMD ./start.sh

