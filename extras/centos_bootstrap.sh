### You'll need to run this as a user with escalated privileges.

### Create the MongoDB Yum repository

cat << EOF > /etc/yum.repos.d/mongodb-org-4.0.repo
[mongodb-org-4.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/4.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.0.asc
EOF

### Prepare the field for Yarn
curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -
wget https://dl.yarnpkg.com/rpm/yarn.repo -O /etc/yum.repos.d/yarn.repo

### Update the OS
yum update -y && yum upgrade -y

### Install the YETI Dependencies
yum groupinstall "Development Tools" -y
yum install epel-release
yum install python-pip git mongodb-org python-devel libxml2-devel libxslt-devel zlib-devel redis firewalld yarn vim curl wget net-tools nginx uwsgi -y
pip install --upgrade pip
pip install uwsgi

### Install YETI
sudo mkdir /var/log/yeti
sudo chown yeti /var/log/yeti
cd /opt
git clone https://github.com/yeti-platform/yeti.git
sudo chown -R yeti:yeti /opt/yeti
cd yeti
pip install -r requirements.txt
yarn install
PWD1=`pwd`

sudo chmod +x $PWD1/extras/systemd/*
sed -i s'/\/usr\/local\/bin\/uwsgi/\/usr\/bin\/uwsgi\ --plugin\ python/g' $PWD1/extras/systemd/yeti_uwsgi.service
sed -i s'/\/usr\/local\/bin/\/usr\/bin/g' $PWD1/extras/systemd/yeti_uwsgi.service
sed -i s'/\/usr\/local\/bin/\/bin/g' $PWD1/extras/systemd/*
sudo ln -s $PWD1/extras/systemd/* /lib/systemd/system/

### Secure your instance
# Add firewall rules for YETI
systemctl enable firewalld
systemctl start firewalld
firewall-cmd  --permanent --zone=public --add-port 5000/tcp
firewall-cmd --reload

# Prepare for startup
systemctl enable mongod
systemctl start mongod

# Launch Yeti
sudo systemctl enable yeti_web.service
sudo systemctl enable yeti_analytics.service
sudo systemctl enable yeti_beat.service
sudo systemctl enable yeti_exports.service
sudo systemctl enable yeti_feeds.service
sudo systemctl enable yeti_oneshot.service
sudo systemctl enable yeti_uwsgi.servic
sudo systemctl enable redis

sudo systemctl start yeti_web.service
sudo systemctl start yeti_analytics.service
sudo systemctl start yeti_beat.service
sudo systemctl start yeti_exports.service
sudo systemctl start yeti_feeds.service
sudo systemctl start yeti_oneshot.service
sudo systemctl start yeti_uwsgi.service
sudo systemctl start redis
