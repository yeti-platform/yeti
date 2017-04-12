# Install dependencies
export LC_ALL="en_US.UTF-8"
apt-get update -y
apt-get install build-essential git python-dev mongodb redis-server libxml2-dev libxslt-dev zlib1g-dev python-virtualenv python-pip nginx -y

# Clone project
cd /opt
git clone https://github.com/yeti-platform/yeti.git

# Install requirements
pip install -r yeti/requirements.txt
pip install uwsgi

# Configure services
useradd yeti
cp yeti/extras/systemd/*.service /lib/systemd/system/
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
cp yeti/extras/nginx/yeti /etc/nginx/sites-available/
ln -s /etc/nginx/sites-available/yeti /etc/nginx/sites-enabled/yeti
service nginx restart

# Start services
sudo systemctl start yeti_uwsgi.service
sudo systemctl start yeti_oneshot.service
sudo systemctl start yeti_feeds.service
sudo systemctl start yeti_exports.service
sudo systemctl start yeti_analytics.service
sudo systemctl start yeti_beat.service
