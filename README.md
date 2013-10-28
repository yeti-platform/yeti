# Malcom - Malware Communication Analyzer

Malcom is a tool designed to analyze a system's network communication using graphical representations of network traffic. This comes handy when analyzing how certain malware species try to communicate with the outside world. 

Malcom can help you: 

* detect central command and control (C&C) servers
* understand peer-to-peer networks
* observe DNS fast-flux infrastructures
* quickly determine if a network artifact is 'known-bad'

The aim of Malcom is to make malware analysis and intel gathering *faster* by providing a human-readable version of network traffic originating from a given host or network. Convert network traffic information to actionable intelligence faster.

Check the [wiki](https://github.com/tomchop/malcom/wiki) for a Quickstart with some nice screenshots and a tutorial on [how to add your own feeds](https://github.com/tomchop/malcom/wiki/Adding-feeds-to-Malcom).

## Quick how-to

* Install
* Elevate your privileges to root (yeah, I know, see [disclaimer](/README.md#Disclaimer))
* Start the webserver with `python malcom.py` (or see options with `python malcom --help`)
** Default port is 8080

## Installation

Malcom is written in python. Provided you have the necessary libraries, you should be able to run it on any platform.

The following was tested on Ubuntu server 12.04 LTS:

* Install `git`, `python` and `libevent` libs, and `mongodb`

        apt-get install git python-dev libevent-dev mongodb

* Get `virtualenv` and `scapy`

        wget https://pypi.python.org/packages/source/v/virtualenv/virtualenv-1.9.tar.gz
        wget http://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz
        tar xvzf virtualenv-1.9.tar.gz
        tar xvzf scapy-latest.tar.gz

* Clone the Git repo

        git clone https://github.com/tomchop/malcom.git malcom

* Create your virtualenv and activate it

        cd malcom
        python ../virtualenv-1.9/virtualenv.py env-malcom
        source env-malcom/bin/activate

* Install scapy, without elevating your privs to root

        cd ~/scapy-2.1.0
        python setup.py install

* still from your virtualenv, install necessary python packages

        pip install flask pymongo pygeoip gevent-websocket python-dateutil netifaces

* If you're planning on using feeds, you might want to install libxml:

        apt-get install libxml2-dev libxslt-dev zlib1g-dev
        pip install lxml


Launch the webserver using `python malcom.py`. Check `python malcom.py --help` for listen interface and ports.

### Environment

Malcom was designed and tested on a Ubuntu Server 12.04 LTS VM.

If you're used to doing malware analysis, you probably already have tons of virtual machines running on a host OS. Just install Malcom on a new VM, and route your other VM's connections through Malcom. Use `enable_routing.sh` to activate routing / NATing on the VM Malcom is running on. You'll need to add an extra network card to the guest OS.

As long as it's getting layer-3 network data, Malcom can be deployed anywhere. Although it's not recommended to use it on high-availability networks (it wasn't designed to be fast, see [disclaimer](/README.md#Disclaimer)), you can have it running at the end of your switch's mirror port or on your gateway.

### Feeds (experimental)

Feeds now run automatically by default. If you want to avoid this behavior, run malcom with the `--no-feeds` option.
Source your virtualenv, and then launch a python shell (i.e. type `python`)

Your database should be populated automatically. If you can dig into the code, adding feeds is pretty straightforward (assuming you're generating `Evil` objects). You can find an example feed in `/feeds/zeustracker`. A more detailed tutorial is [available here](https://github.com/tomchop/malcom/wiki/Adding-feeds-to-Malcom).


## Technical specs

Malcom was written mostly from scratch, in Python. It uses the following frameworks to work: 

* [flask](http://flask.pocoo.org/) - a lightweight python web framework
* [mongodb](http://www.mongodb.org/) - a NoSQL database. It interfaces to python with [pymongo](http://api.mongodb.org/python/current/)
* [d3js](http://d3js.org/) - a JavaScript library that produces awesome force-directed graphs (https://github.com/mbostock/d3/wiki/Gallery)
* [bootstrap](http://twitter.github.io/bootstrap/) - a CSS framework that will eventually kill webdesign, but makes it extremely easy to quickly "webize" applications that are functionnal in command line without caring spending too much time on HTML and CSS.

## Roadmap

My todo list is a text file on my desktop, its items are written in three different languages and I don't really think anyone else than me could understand the acronyms.

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

Please note that MongoDB, d3js, Maximind and Bootstrap (and other third party libraries included in Malcom) may have their own GPL compatible licences.
