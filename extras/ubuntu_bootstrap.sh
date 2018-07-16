# Install dependencies
export LC_ALL="en_US.UTF-8"

if [ -f "/usr/bin/apt" ]; then
   APT="/usr/bin/apt"
else
   APT="/usr/bin/apt-get"
fi

$APT update -y
$APT install dirmngr

curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

# https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4

# https://wiki.ubuntu.com/Releases
OS_CODENAME=`lsb_release -c --short`

if [ $OS_CODENAME == "bionic" || $OS_CODENAME == "artful" || $OS_CODENAME == "zesty" || $OS_CODENAME == "yakkety" || $OS_CODENAME == "xenial" ]; then
  echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/4.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.0.list
elif [ $OS_CODENAME == "wily" || $OS_CODENAME == "vivid" || $OS_CODENAME == "utopic" || $OS_CODENAME == "trusty" ]; then
  echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
else
  echo "[!] Installing on an unsupported or outdated version of Ubuntu, trying Trusty package for Mongo"
  echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
fi

$APT update -y
$APT install build-essential git python-dev mongodb-org redis-server libcurl3 libxml2-dev libxslt-dev zlib1g-dev python-virtualenv python-pip nginx yarn -y

# Clone project
cd /opt
git clone https://github.com/yeti-platform/yeti.git

# Install requirements
cd /opt/yeti
pip install -r requirements.txt
pip install uwsgi
yarn install

# Configure services
useradd yeti
cp extras/systemd/*.service /etc/systemd/system/
systemctl enable mongod.service
systemctl enable yeti_uwsgi.service
systemctl enable yeti_oneshot.service
systemctl enable yeti_feeds.service
systemctl enable yeti_exports.service
systemctl enable yeti_analytics.service
systemctl enable yeti_beat.service
systemctl daemon-reload
chown -R yeti:yeti /opt/yeti
chmod +x /opt/yeti/yeti.py

# Configure nginx
rm /etc/nginx/sites-enabled/default
cp extras/nginx/yeti /etc/nginx/sites-available/
ln -s /etc/nginx/sites-available/yeti /etc/nginx/sites-enabled/yeti
service nginx restart

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
