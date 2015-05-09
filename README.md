# Malcom - Malware Communication Analyzer

Malcom is a tool designed to analyze a system's network communication using graphical representations of network traffic, and cross-reference them with known malware sources. This comes handy when analyzing how certain malware species try to communicate with the outside world.

- [What is Malcom?](#what-is-malcom)
- [Quick how-to](#quick-how-to)
- [Installation](#installation)
 - [Configuration options](#configuration-options)
 - [Docker instance](#docker-instance)
 - [Quick note on TLS interception](#quick-note-on-tls-interception)
 - [Environment](#environment)
 - [Feeds](#feeds)
- [Technical specs](#technical-specs)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [License](#license)

# What is Malcom?

Malcom can help you:

* detect central command and control (C&C) servers
* understand peer-to-peer networks
* observe DNS fast-flux infrastructures
* quickly determine if a network artifact is 'known-bad'

The aim of Malcom is to make malware analysis and intel gathering *faster* by providing a human-readable version of network traffic originating from a given host or network. Convert network traffic information to actionable intelligence faster.

Check the [wiki](https://github.com/tomchop/malcom/wiki) for a Quickstart with some nice screenshots and a tutorial on [how to add your own feeds](https://github.com/tomchop/malcom/wiki/Adding-feeds-to-Malcom).

If you need some help, or want to contribute, feel free to join the [mailing list](https://groups.google.com/forum/#!forum/malcom-users) or try to grab someone on IRC (#malcom on freenode.net, it's pretty quiet but there's always someone around). You can also hit me up on twitter [@tomchop_](https://twitter.com/tomchop_)

Here's an example graph for host tomchop.me
![nodes-tomchop.png](http://direct.tomchop.me/malcom/nodes-tomchop.png)

Dataset view (filtered to only show IPs)
![nodes-tomchop.png](http://direct.tomchop.me/malcom/dataset-view.png)


## Quick how-to

* Install
* Make sure `mongodb` and `redis-server` are running
* Elevate your privileges to root (yeah, I know, see [disclaimer](/README.md#Disclaimer))
* Start the webserver using the default configuration with `./malcom.py -c malcom.conf` (or see options with `./malcom.py --help`)
** For an example configuration file, you can copy `malcom.conf.example` to `malcom.conf`
** Default port is 8080
** Alternatively, run the feeds from `celery`. See the [feeds](/README.md#Feeds) section for details on how to to this.

## Installation

Malcom is written in python. Provided you have the necessary libraries, you should be able to run it on any platform. I highly recommend the use of python virtual environments (`virtualenv`) so as not to mess up your system libraries.

The following was tested on Ubuntu server 14.04 LTS:

* Install `git`, `python` and `libevent` libs, `mongodb`, `redis`, and other dependencies

        $ apt-get install build-essential git python-dev libevent-dev mongodb libxml2-dev libxslt-dev zlib1g-dev redis-server libffi-dev libssl-dev python-virtualenv

* Get `scapy`:

        $ wget http://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz
        $ tar xvzf scapy-latest.tar.gz

* Clone the Git repo:

        $ git clone https://github.com/tomchop/malcom.git malcom

* Create your virtualenv and activate it:

        $ cd malcom
        $ virtualenv env-malcom
        $ source env-malcom/bin/activate

* Install scapy (if you're ina virtual environment, don't  `sudo`):

        $ cd ../scapy-2.1.0
        $ python setup.py install

* Still from your virtualenv, install necessary python packages from the `requirements.txt` file:

        $ cd ../malcom
        $ pip install -r requirements.txt

* For IP geolocation to work, you need to download the [Maxmind](http://dev.maxmind.com/) database and extract the file to the `malcom/Malcom/auxiliary/geoIP` directory. You can get Maxmind's free (and thus more or less accurate) database from the following link: http://dev.maxmind.com/geoip/geoip2/geolite2/:

        $ cd malcom/Malcom/auxiliary/geoIP
        $ wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
        $ gunzip -d GeoLite2-City.mmdb.gz
        $ mv GeoLite2-City.mmdb GeoIP2-City.mmdb

* Launch the webserver from the `malcom` directory using `./malcom.py`. Check `./malcom.py --help` for listen interface and ports.
  * For starters, you can copy the `malcom.conf.example` file to `malcom.conf` and run `./malcom.py -c malcom.conf`

### Configuration options

#### Database

By default, Malcom will try to connect to a local mongodb instance and create its own database, named `malcom`. If this is OK for you, you may skip the following steps. Otherwise, you need to edit the `database` section of your `malcom.conf` file.

##### Set an other name for your Malcom database

By default, Malcom will use a database named `malcom`. You can change this behavior by editing the `malcom.conf` file and setting the `name` directive from the `database` section to your liking.

        [database]
        ...
        name = my_malcom_database
        ...

##### Remote database(s)

By default, Malcom will try to connect to `localhost`, but your database may be on another server. To change this, just set the `hosts` directive. You may use hostnames or IPv4/v6 addresses (just keep in mind to enclose your IPv6 addresses between `[` and `]`, e.g. `[::1]`).

If you'd like to use a standalone database on host `my.mongo.server`, just set:

        [database]
        ...
        hosts = my.mongo.server
        ...

You can also specify the port mongod is listening on by specifying it after the name/address of your server, separated with a `:`

        [database]
        ...
        hosts = localhost:27008
        ...

And if you're using a `ReplicaSet` regrouping `my.mongo1.server` and `my.mongo2.server`, just set:

        [database]
        ...
        hosts = my.mongo1.server,my.mongo2.server
        ...

##### Use authentication

You may have configured your mongod instances to enforce authenticated connections. In that case, you have to set the username the driver will have to use to connect to your mongod instance. To do this, just add a `username` directive to the `database` section in the `malcom.conf` file. You may also have to set the password with the `password` directive. If the user does not have a password, just ignore (i.e. comment out) the `password` directive.

        [database]
        ...
        username = my_user
        password = change_me
        ...

If the user is not linked to the `malcom` database but to another one (for example the `admin` database for a admin user), you will have to set the `authentication_database` directive with the name of that database.

        [database]
        ...
        authentication_database = some_other_database
        ...

##### Case of a replica set

When using a replica set, you may need to ensure you are connected to the right one. For that, just add the `replset` directive to force the mongo driver to check the name of the replicaset

        [database]
        ...
        replset = my_mongo_replica
        ...

By default, Malcom will try to connect to the primary node of th replica set. You may need/want to change that. In order to change that behaviour, just set the `read_preference` directive. See [the mongo documentation](http://docs.mongodb.org/manual/core/read-preference/) for more information.

        [database]
        ...
        read_preference = NEAREST
        ...

Supported read preferences are:
* PRIMARY
* PRIMARY\_PREFERRED
* SECONDARY
* SECONDARY\_PREFERRED
* NEAREST

### Docker instance

The quickest way to get you started is to pull the Docker image from the [public docker repo](https://registry.hub.docker.com/u/tomchop/malcom/). **To pull the automatic Docker build for the latest GitHub commit**, use `tomchop/malcom-automatic` instead of `tomchop/malcom`.

        $ sudo docker pull tomchop/malcom
        $ sudo docker run -P -d --name malcom tomchop/malcom
        
Connect to your malcom instance by checking the port on the docker file.

        $ sudo docker port malcom
        8080/tcp -> 0.0.0.0:49155

Connecting to `http://<docker_host>:49155/` should get you started.

### Quick note on TLS interception

Malcom now supports TLS interception. For this to work, you need to generate some keys in Malcom/networking/tlsproxy/keys. See the KEYS.md file there for more information on how to do this.

Make sure you also have IPtables (you already should) and permissions to do some port forwarding with it (you usually need to be root for that).
You can to this using the convenient `forward_port.sh` script. For example, to intercept all TLS communications towards port 443, use `forward_port.sh 443 9999`. You'll then have to tell malcom to run an interception proxy on port `9999`.

Expect this process to be automated in future releases.

### Environment

Malcom was designed and tested on a Ubuntu Server 14.04 LTS VM.

If you're used to doing malware analysis, you probably already have tons of virtual machines running on a host OS. Just install Malcom on a new VM, and route your other VM's connections through Malcom. Use `enable_routing.sh` to activate routing / NATing on the VM Malcom is running on. You'll need to add an extra network card to the guest OS.

As long as it's getting layer-3 network data, Malcom can be deployed anywhere. Although it's not recommended to use it on high-availability networks (it wasn't designed to be fast, see [disclaimer](/README.md#Disclaimer)), you can have it running at the end of your switch's mirror port or on your gateway.

### Feeds

To launch an instance of Malcom that ONLY fetches information from feeds, run Malcom with the `--feeds` option or tweak the configuration file.

Your database should be populated automatically. If you can dig into the code, adding feeds is pretty straightforward (assuming you're generating `Evil` objects). You can find an example feed in `/feeds/zeustracker`. A more detailed tutorial is [available here](https://github.com/tomchop/malcom/wiki/Adding-feeds-to-Malcom).

You can also use `celery` to run feeds. Make sure celery is installed by running `$ pip install celery` from your virtualenv. You can then use `celery worker -E --config=celeryconfig  --loglevel=DEBUG --concurrency=12` to launch the feeding process with 12 simultaneous workers.

## Technical specs

Malcom was written mostly from scratch, in Python. It uses the following frameworks to work:

* [flask](http://flask.pocoo.org/) - a lightweight python web framework
* [mongodb](http://www.mongodb.org/) - a NoSQL database. It interfaces to python with [pymongo](http://api.mongodb.org/python/current/)
* [redis](redis.io) - An advanced in-memory key-value store
* [d3js](http://d3js.org/) - a JavaScript library that produces awesome force-directed graphs (https://github.com/mbostock/d3/wiki/Gallery)
* [bootstrap](http://twitter.github.io/bootstrap/) - a CSS framework that will eventually kill webdesign, but makes it extremely easy to quickly "webize" applications that would only work through a command prompt.

## Roadmap

**Collaboration** - The **main** direction I want this tool to take is to become collaborative. I have a few ideas for this, and I think it will become 100x more useful once data sharing is implemented.

**Extendability** - The other thing I want to include in the tool is the ability to more easily extend it. I don't have the same needs as everyone else, and this tool was conceived having my needs in mind. You can now customize Malcom by [adding new feeds](https://github.com/tomchop/malcom/wiki/Adding-feeds-to-Malcom).

Once collaboration and extension are up and running, I think this will be helpful for more than one incident responder out there. :-)

## Disclaimer

This tool was coded during my free time. Like a huge number of tools we download and use daily, I wouldn't recommend to use it on a production environment where data stability and reliability is a MUST.

* It may be broken, have security gaps (running it as root in uncontrolled environments is probably not a good idea), or not work at all.
* It's written in python, so don't expect it to be ultra-fast or handle huge amounts of data easily.
* I'm no coder, so don't expect to see beautiful pythonic code everywhere you look. Or lots of comments.

It's in early stages of development, meaning "it works for me". You're free to share it, improve it, ask for pull requests.

## License

Malcom - Malware communications analyzer
Copyright (C) 2013 Thomas Chopitea

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Please note that Redis, MongoDB, d3js, Maximind and Bootstrap (and other third party libraries included in Malcom) may have their own GPL compatible licences.
