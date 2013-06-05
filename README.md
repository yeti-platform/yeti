Malcom - Malware Communication Analyzer
=======================================

Malcom is a graphical tool designed to better analyze a system's network communication. This comes handy when analyzing how certain malware instances try to communicate with the outside world. 

Malcom can help you: 

* detect central command and control (C&C) servers
* understand peer-to-peer networks
* observe DNS fast-flux infrastructures

The aim of Malcom is to make malware analysis *faster* by providing a human-readable version of network traffic originating from a given host or network.


Technical specs
---------------

Malcom was written mostly from scratch, in Python. It uses the following frameworks to work: 

* flask - a lightweight python web framework
* d3js - a JavaScript library that produces awesome force-directed graphs
* bootstrap - a CSS framework that will ultimately uniform the aspect of websites, but makes it extremely easy to quickly produce webapps without having to focus on the HTML and CSS
* 



Installation
------------

Environment:
VM (debian?)
two interfaces
virtualenv

Packages:
Everything you need is in requirements.txt. Install using 

pip install -r requirements.txt

Two packages are used that cannot be installed with pip

* Scapy 
** Get it from http://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz
** Untar, build, and install from your virtualenv shell

* Faup
** Get it from https://github.com/stricaud/faup
** Follow installation instructions at the end of https://github.com/stricaud/faup/blob/master/README.md
** Go to the python bindings directory: faup/src/lib/bindings/python/
*** python setup.py build
*** python setup.py install (from your virtualenv)

This should get you up and running