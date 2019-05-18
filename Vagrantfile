# frozen_string_literal: true

# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.

Vagrant.configure("2") do |config|
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "ubuntu/xenial64"

  # Automatic Vagrant Box Update check (don't turn this off)
  config.vm.box_check_update = true

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:
    vb.memory = "4024"
  end

  # Configure auto-mounting local directory (location of the Yeti Git Repo, cloned locally) into the Vagrant Box.

  config.vm.synced_folder "./", "/opt/yeti", mount_options: ["uid=2001", "gid=2001"]

  # Provision the Vagrant Box with the necessary configurations.

  config.vm.provision "shell", inline: <<-SHELL

    sudo useradd -u 2001 -G sudo yeti

    # Mount the referenced sync'd folder from above.  There is a gotcha here as Vagrant auto-names the mountpoint,
    # so any adjustment to the path will adjust the naming convention below (opt_yet).

    sudo mount -t vboxsf -o uid=`id -u yeti`,gid=`id -g yeti` opt_yeti /opt/yeti

    # Create and change ownership for the default Yeti install location. default = /opt/yet | user=yeti, group=yeti
    # These defaults can be changed, but systemd files must be altered to match.

    mkdir -p /opt/yeti
    mkdir -p /var/log/yeti
    chown yeti:yeti /opt/yeti
    chown yeti:yeti /var/log/yeti
    cd /opt/yeti

    # Install the Yarn Repo (required by Yeti)
    export LC_ALL="en_US.UTF-8"
    curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
    echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
    curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -

    # Install Yeti package dependencies.

    sudo apt-get update -y
    sudo apt-get install build-essential git python-dev mongodb redis-server libxml2-dev libxslt-dev zlib1g-dev python-virtualenv python-pip nginx yarn -y
    sudo pip install --upgrade pip
    pip install -r requirements.txt
    sudo pip install uwsgi
    yarn install

    # Enable Yeti services via systemd. (*NOTE* The user yeti and default path of /opt/yet are hard coded)

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

    # Configure NGINX as the web server fronting UWSGI

    rm /etc/nginx/sites-enabled/default
    cp extras/nginx/yeti /etc/nginx/sites-available/
    ln -s /etc/nginx/sites-available/yeti /etc/nginx/sites-enabled/yeti
    service nginx restart

    # Start Yeti services

    echo "[+] Starting services..."
    sudo systemctl restart yeti_oneshot.service
    sleep 5
    sudo systemctl restart yeti_feeds.service
    sudo systemctl restart yeti_exports.service
    sudo systemctl restart yeti_analytics.service
    sudo systemctl restart yeti_beat.service
    sudo systemctl restart yeti_uwsgi.service

    echo "[+] Yeti successfully installed. Webservice listening on tcp/80"

    sudo systemctl status yeti_oneshot.service
    sudo systemctl status yeti_feeds.service
    sudo systemctl status yeti_exports.service
    sudo systemctl status yeti_analytics.service
    sudo systemctl status yeti_beat.service
    sudo systemctl status yeti_uwsgi.service

  SHELL
  # End statement of provisioning script.
end # End of Vagrant Config File.
