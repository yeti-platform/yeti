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

### Prepare the field for Yarn
curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -
curl -L https://dl.yarnpkg.com/rpm/yarn.repo -o /etc/yum.repos.d/yarn.repo

### Update the OS
sudo yum update -y && yum upgrade -y

### Install the YETI Dependencies
sudo yum groupinstall "Development Tools" -y
sudo yum install epel-release
sudo yum install python-pip git mongodb-org python-devel nodejs libxml2-devel libxslt-devel zlib-devel redis firewalld yarn -y
sudo pip install --upgrade pip

### Install YETI
git clone https://github.com/yeti-platform/yeti.git
cd yeti
sudo pip install -r requirements.txt
yarn install

### Secure your instance
# Add firewall rules for YETI
sudo systemctl enable firewalld
sudo systemctl start firewalld
sudo firewall-cmd --add-port 5000/tcp --permanent
sudo firewall-cmd --reload

# Prepare for startup
systemctl enable mongod
systemctl start mongod

# Launch Yeti
cd yeti
./yeti.py webserver
