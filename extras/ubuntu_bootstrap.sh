# Install dependencies
export LC_ALL="en_US.UTF-8"
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

apt-get update -y
apt-get install build-essential git python-dev mongodb redis-server libxml2-dev libxslt-dev zlib1g-dev python-virtualenv python-pip nginx yarn -y

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
sudo systemctl start yeti_oneshot.service
sleep 5
sudo systemctl start yeti_feeds.service
sudo systemctl start yeti_exports.service
sudo systemctl start yeti_analytics.service
sudo systemctl start yeti_beat.service
sudo systemctl start yeti_uwsgi.service

echo "[+] Yeti succesfully installed. Webserver listening on tcp/80"
