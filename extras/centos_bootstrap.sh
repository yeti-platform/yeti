#!/bin/bash

### Create the MongoDB Yum repository
cat << EOF > /etc/yum.repos.d/mongodb-org-3.4.repo
[mongodb-org-3.4]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/3.4/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-3.4.asc
EOF

### Prepare the field for Yarn
curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -
curl https://dl.yarnpkg.com/rpm/yarn.repo -o /etc/yum.repos.d/yarn.repo

### Update the OS
yum update -y && yum upgrade -y

### Install the YETI Dependencies
yum groupinstall "Development Tools" -y
yum install epel-release -y
yes | yum install python-pip git mongodb-org gcc-c++ make python-devel libxml2-devel libxslt-devel zlib-devel redis firewalld yarn nginx nodejs uwsgi uwsgi-plugin-python -y

### Install YETI
mkdir /opt/yeti
git clone https://github.com/yeti-platform/yeti.git /opt/yeti
pip install --upgrade pip
pip install -r /opt/yeti/requirements.txt
# Need to do the yarn install without having to go into the directory
cd /opt/yeti
yarn install
cd ~

# Create the YETI user
useradd -s /usr/sbin/nologin yeti

# Give the yeti user ownership of the /opt/yeti directory
chown -R yeti:yeti /opt/yeti

### Secure your instance
# Add firewall rules for YETI
# Port 80 - Nginx
# Port 5000 - YETI <- might be replaced by uwsgi
# Port 8000 - uwsgi
# Port 9191 - Redis
systemctl start firewalld
firewall-cmd --add-port=80/tcp --add-port=8000/tcp --add-port=9191/tcp --add-port=5000/tcp --permanent
firewall-cmd --reload

# Create systemd services
rm -f /opt/yeti/extras/systemd/yeti_web.service
sed -i 's/\/usr\/local\/bin/\/bin/' /opt/yeti/extras/systemd/yeti_analytics.service
sed -i 's/\/usr\/local\/bin/\/bin/' /opt/yeti/extras/systemd/yeti_beat.service
sed -i 's/\/usr\/local\/bin/\/bin/' /opt/yeti/extras/systemd/yeti_exports.service
sed -i 's/\/usr\/local\/bin/\/bin/' /opt/yeti/extras/systemd/yeti_feeds.service
sed -i 's/\/usr\/local\/bin/\/bin/' /opt/yeti/extras/systemd/yeti_oneshot.service
sed -i 's/\/usr\/local\/bin\/uwsgi/\/sbin\/uwsgi\ --plugin\ python/' /opt/yeti/extras/systemd/yeti_uwsgi.service
# sed -i 's/\/usr\/local\/bin/\/sbin/' /opt/yeti/extras/systemd/yeti_uwsgi.service

cp /opt/yeti/extras/systemd/* /lib/systemd/system/

# Prep nginx
cp /opt/yeti/extras/nginx/yeti /etc/nginx/conf.d/yeti.conf

# Configure services to start on boot
systemctl enable mongod.service
systemctl enable redis.service
systemctl enable firewalld.service
systemctl enable yeti_analytics.service
systemctl enable yeti_beat.service
systemctl enable yeti_exports.service
systemctl enable yeti_feeds.service
systemctl enable yeti_oneshot.service
# systemctl enable yeti_uwsgi.service
systemctl enable nginx.service

# Start all the YETI services
systemctl start mongod.service
systemctl start redis.service
systemctl start yeti_analytics.service
systemctl start yeti_feeds.service
systemctl start yeti_oneshot.service
systemctl start yeti_exports.service
systemctl start yeti_beat.service
# systemctl start yeti_uwsgi.service
systemctl start nginx.service

# Launch Yeti < should be replaced by uwsgi
# cd yeti
# ./yeti.py webserver
