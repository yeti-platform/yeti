#!/bin/bash

set -e

#Check execution with root

if [[ "$EUID" -ne "0" ]]; then
	echo "Run this script as root"
fi

if [ -f "/usr/bin/apt" ]; then
   APT="/usr/bin/apt"
else
   APT="/usr/bin/apt-get"
fi

$APT update -y
$APT install -y dirmngr gnupg apt-transport-https curl wget

curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | apt-key add -
echo "deb https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.4.list

$APT update -y
$APT install -y build-essential git python-dev mongodb-org mongodb-org-server mongodb-org-mongos mongodb-org-shell redis-server libcurl4 libxml2-dev libxslt-dev zlib1g-dev python-virtualenv python-pip python3-pip nginx yarn uwsgi-plugin-python3

# Clone project
cd /opt
git clone https://github.com/yeti-platform/yeti.git

# Install requirements
cd /opt/yeti
pip3 install -r requirements.txt
pip3 install uwsgi
yarn install

# Configure services
useradd -r -M -d /opt/yeti -s /usr/sbin/nologin yeti
sudo mkdir /var/log/yeti
sudo chown yeti /var/log/yeti
chown -R yeti:yeti /opt/yeti
chmod +x /opt/yeti/yeti.py
cp extras/systemd/*.service /etc/systemd/system/
systemctl enable mongod.service
systemctl enable yeti_uwsgi.service
systemctl enable yeti_oneshot.service
systemctl enable yeti_feeds.service
systemctl enable yeti_exports.service
systemctl enable yeti_analytics.service
systemctl enable yeti_beat.service
systemctl daemon-reload

# Configure nginx
rm /etc/nginx/sites-enabled/default
cp extras/nginx/yeti /etc/nginx/sites-available/
ln -s /etc/nginx/sites-available/yeti /etc/nginx/sites-enabled/yeti
systemctl reload nginx

# Start services
echo "[+] Starting services..."
systemctl start mongod.service
systemctl start yeti_oneshot.service
sleep 5
systemctl start yeti_feeds.service
systemctl start yeti_exports.service
systemctl start yeti_analytics.service
systemctl start yeti_beat.service
systemctl start yeti_uwsgi.service

echo "[+] Yeti succesfully installed. Webserver listening on tcp/80"
