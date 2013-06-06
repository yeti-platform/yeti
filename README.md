# Malcom - Malware Communication Analyzer

Malcom is a tool designed to analyze a system's network communication using graphical representations of network traffic. This comes handy when analyzing how certain malware species try to communicate with the outside world. 

Malcom can help you: 

* detect central command and control (C&C) servers
* understand peer-to-peer networks
* observe DNS fast-flux infrastructures

The aim of Malcom is to make malware analysis *faster* by providing a human-readable version of network traffic originating from a given host or network. Convert network traffic information to actionable intelligence faster.

In the near future, it will also become a collaborative tool (coming soon!)

## Quick how-to

* Install
* Elevate your privileges to root (yeah, I know, see [disclaimer](/README.md#Disclaimer))
* Start the webserver with `python server.py`
** Default port is 8080
** If you want to change ports and stuff, just edit server.py directly

## Installation

Malcom is written in python. Provided you have the necessary libraries, you should be able to run it on any platform.

### Environment

Malcom was designed and tested on a Debian Wheezy VM.

If you're used to doing malware analysis, you probably already have tons of virtual machines running on a host OS. Just install Malcom on a new VM, and route your other VM's connections through Malcom. Use the `enable_routing.sh` to activate routing / NATing on the VM Malcom is running on. You'll need to add an extra network card to the guest OS.

As long as it's getting layer-3 network data, Malcom can be deployed anywhere. Although it's not recommended to use it on high-availability networks (it wasn't designed to be fast, see [disclaimer](/README.md#Disclaimer)), you can have it running at the end of your switch's mirror port or on your gateway.

### Packages

Everything you need is in requirements.txt. Install using `pip install -r requirements.txt`

* Scapy (won't install from pip)
** Get it from http://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz
** Untar, build, and install from your virtualenv shell

## Technical specs

Malcom was written mostly from scratch, in Python. It uses the following frameworks to work: 

* [flask](http://flask.pocoo.org/) - a lightweight python web framework
* [mongodb](http://www.mongodb.org/) - a NoSQL database. It interfaces to python with [pymongo](http://api.mongodb.org/python/current/)
* [d3js](http://d3js.org/) - a JavaScript library that produces awesome force-directed graphs (https://github.com/mbostock/d3/wiki/Gallery)
* [bootstrap](http://twitter.github.io/bootstrap/) - a CSS framework that will eventually kill webdesign, but makes it extremely easy to quickly produce webapps without having to focus on the HTML and CSS

## Roadmap

My todo list is a text file on my desktop, its items are written in three different languages and I don't really think anyone else than me could understand the acronyms.

**Collaboration** - The **main** direction I want this tool to take is to become collaborative. I have a few ideas for this, and I think it will become 100x more useful once data sharing is implemented.

**Extendability** - The other thing I want to include in the tool is the ability to more easily extend it. I don't have the same needs as everyone else, and this tool was conceived having my needs in mind.

Once collaboration and extension are up and running, I think this will be helpful for more than one incident responder out there. :-)

## Disclaimer

This tool was coded during my free time. Like a huge number of tools we download and use daily, I wouldn't recommend to use it on a production environment where data stability is a MUST.

* It may be broken, have security gaps (running as root is probably not a good idea), or not work at all. 
* It's written in python, so don't expect it to be ultra-fast or handle huge amounts of data easily. 
* I'm no coder, so don't expect to see beautiful pythonic code everywhere you look. Or lots of comments.

It's version 0.1, meaning "it works for me". You're free to share it, improve it, ask for pull requests.

## License

Malcom is subject to the [MIT License](http://opensource.org/licenses/MIT). It's yours to build on top and do whatever you like with the result :-)