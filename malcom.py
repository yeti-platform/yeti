#!/usr/bin/env python
# -*- coding: utf-8 -*-

__description__ = 'Malcom - Malware communications analyzer'
__author__ = '@tomchop_'
__version__ = '1.1 alpha'
__license__ = "GPL"

import os, sys, argparse, threading
import netifaces as ni
from time import sleep

from flask import Flask

from Malcom.analytics.analytics import Analytics
from Malcom.feeds.feed import FeedEngine
from Malcom.web.webserver import MalcomWeb
from Malcom.networking.tlsproxy.tlsproxy import MalcomTLSProxy
import Malcom # this is the configuraiton

# this should be stored and loaded from a configuration file
Malcom.config['DEBUG'] = True
Malcom.config['VERSION'] = "1.1 alpha"
Malcom.config['LISTEN_INTERFACE'] = "0.0.0.0"
Malcom.config['LISTEN_PORT'] = 8080
Malcom.config['MAX_THREADS'] = 4
Malcom.config['PUBLIC'] = False
Malcom.config['NO_FEED'] = False
Malcom.config['TLS_PROXY_PORT'] = False

Malcom.config['IFACES'] = {}
for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
	Malcom.config['IFACES'][i] = ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']

if __name__ == "__main__":

	# options
	parser = argparse.ArgumentParser(description="Malcom - malware communications analyzer")
	parser.add_argument("-a", "--analytics", help="Run analytics", action="store_true", default=False)
	parser.add_argument("-f", "--feeds", help="Run feeds (use -ff to force run on all feeds)", action="count")
	parser.add_argument("-i", "--interface", help="Listen interface", default=Malcom.config['LISTEN_INTERFACE'])
	parser.add_argument("-p", "--port", help="Listen port", type=int, default=Malcom.config['LISTEN_PORT'])
	parser.add_argument("--public", help="Run a public instance (Feeds and network sniffing disabled)", action="store_true", default=Malcom.config['PUBLIC'])
	parser.add_argument("--max-threads", help="Number of threads to use (default 4)", type=int, default=Malcom.config['MAX_THREADS'])
	parser.add_argument("--tls-proxy-port", help="Port number on which to start the TLS proxy on. No proxy started if not specified.", type=int, default=Malcom.config['TLS_PROXY_PORT'])
	
	#parser.add_argument("--no-feeds", help="Disable automatic feeding", action="store_true", default=app.config['NO_FEED'])
	args = parser.parse_args()

	os.system('clear')
	Malcom.config['LISTEN_INTERFACE'] = args.interface
	Malcom.config['LISTEN_PORT'] = args.port
	Malcom.config['MAX_THREADS'] = args.max_threads
	Malcom.config['PUBLIC'] = args.public

	sys.stderr.write("===== Malcom %s - Malware Communications Analyzer =====\n\n" % Malcom.config['VERSION'])
	
	sys.stderr.write("Detected interfaces:\n")
	for iface in Malcom.config['IFACES']:
		sys.stderr.write("%s:\t%s\n" % (iface, Malcom.config['IFACES'][iface]))

	sys.stderr.write("Importing feeds...\n")
	Malcom.analytics_engine = Analytics()
	
	if args.tls_proxy_port:
		sys.stderr.write("Starting TLS proxy on port %s\n" % args.tls_proxy_port)
		Malcom.tls_proxy = MalcomTLSProxy(args.tls_proxy_port)
		Malcom.tls_proxy.start()

	Malcom.feed_engine = FeedEngine(Malcom.analytics_engine)
	Malcom.feed_engine.load_feeds()

	# call malcom to run feeds - this will not start the web interface
	if args.feeds >= 1:
		if args.feeds == 1:
			try:
				Malcom.feed_engine.start()
				sys.stderr.write("Starting feed scheduler...\n")
				while True:
					raw_input()
			except KeyboardInterrupt:
				sys.stderr.write("\nStopping all feeds...\n")
				Malcom.feed_engine.stop_all_feeds()
				exit(0)
			
		elif args.feeds == 2:
			Malcom.feed_engine.run_all_feeds()
		exit(0)

	elif args.analytics: # run analytics
		
		Malcom.analytics_engine.max_threads = threading.Semaphore(Malcom.config['MAX_THREADS'])

		while True:
			Malcom.analytics_engine.process()
			sleep(10) # sleep 10 seconds
		pass

	else: # run webserver
		web = MalcomWeb(Malcom.config['PUBLIC'], Malcom.config['LISTEN_PORT'], Malcom.config['LISTEN_INTERFACE'])
		try:
			Malcom.tls_proxy.stop()
		except Exception, e:
			pass
			

		exit(0)
