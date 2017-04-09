### You'll need to run this as a user with escalated privileges. 

### Create the MongoDB Yum repository

cat << EOF > /etc/yum.repos.d/mongodb-org-3.4.repo
[mongodb-org-3.4]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/3.4/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-3.4.asc
EOF
### Update the OS
yum update -y && yum upgrade -y

### Install the YETI Dependencies
yum groupinstall "Development Tools" -y
yum install epel-release
yum install python-pip git mongodb-org python-devel libxml2-devel libxslt-devel zlib-devel redis firewalld -y
pip install --upgrade pip

### Install YETI
git clone https://github.com/yeti-platform/yeti.git
pip install -r yeti/requirements.txt

### Secure your instance
# Add firewall rules for Redis, Mongodb, and YETI
systemctl enable firewalld
systemctl start firewalld
firewall-cmd  --permanent --zone=public --add-port 6379/tcp
firewall-cmd  --permanent --zone=public --add-port 27017/tcp
firewall-cmd  --permanent --zone=public --add-port 5000/tcp
firewall-cmd --reload

# Prepare for startup
systemctl enable mongod
systemctl start mongod
