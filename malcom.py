#!/usr/bin/env python
# -*- coding: utf-8 -*-

__description__ = 'Malcom - Malware communications analyzer'
__author__ = '@tomchop_'
__version__ = '1.2 alpha'
__license__ = "GPL"

import os, sys, argparse, threading
import netifaces as ni
from time import sleep
from multiprocessing import Pipe

from flask import Flask

import Malcom # this is the configuration
from Malcom.analytics.analytics import Analytics

# this should be stored and loaded from a configuration file
Malcom.config['DEBUG'] = True
Malcom.config['VERSION'] = "1.2 alpha"

Malcom.config['LISTEN_INTERFACE'] = "0.0.0.0"
Malcom.config['LISTEN_PORT'] = 8080
Malcom.config['MAX_WORKERS'] = 4
Malcom.config['PUBLIC'] = False
Malcom.config['TLS_PROXY_PORT'] = False
Malcom.config['FEEDS'] = False
Malcom.config['ANALYTICS'] = False

Malcom.config['BASE_PATH'] = os.getcwd() + '/Malcom'
Malcom.config['SNIFFER_DIR'] = Malcom.config['BASE_PATH'] + '/sniffer'
Malcom.config['FEEDS_DIR'] = Malcom.config['BASE_PATH'] + '/feeds'

Malcom.config['IFACES'] = {}
for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
	Malcom.config['IFACES'][i] = ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']


def parse_config(filename):
	import ConfigParser
	config = ConfigParser.ConfigParser()
	config.read(filename)

	sections = config.sections()

	for section in sections:
		try:
			if section == 'web':
				Malcom.config['WEB'] = config.getboolean(section, 'activated')
				Malcom.config['LISTEN_INTERFACE'] = config.get(section, 'listen_interface')
				Malcom.config['LISTEN_PORT'] = config.getint(section, 'listen_port')
				Malcom.config['PUBLIC'] = config.getboolean(section, 'public')

			if section == 'analytics':
				Malcom.config['ANALYTICS'] = config.getboolean(section, 'activated')
				Malcom.config['MAX_WORKERS'] = config.getint(section, 'max_workers')

			if section == 'feeds':
				Malcom.config['FEEDS'] = config.getboolean(section, 'activated')
				Malcom.config['FEEDS_DIR'] = config.get(section, 'feeds_dir')
				Malcom.config['FEEDS_SCHEDULER'] = config.getboolean(section, 'scheduler')

			if section == 'sniffer':
				Malcom.config['SNIFFER'] = config.getboolean(section, 'activated')
				Malcom.config['SNIFFER_DIR'] = config.get(section, 'sniffer_dir')
				Malcom.config['TLS_PROXY_PORT'] = config.getint(section, 'tls_proxy_port')

			# deal with DB origins
			if section.startswith("db_"):
				pass

		except Exception, e:
				sys.stderr.write("Configuration file failed to load: %s\nBailing...\n\n" % e)
				exit(-1)

	#print Malcom.config
	
	sys.stderr.write("Successfully loaded configuration file from %s\n" % filename)
	pass

if __name__ == "__main__":

	# options
	parser = argparse.ArgumentParser(description="Malcom - malware communications analyzer")
	parser.add_argument("-a", "--analytics", help="Run analytics", action="store_true", default=False)
	parser.add_argument("-f", "--feeds", help="Run feeds", action="store_true", default=False)
	parser.add_argument("-i", "--interface", help="Listen interface", default="0.0.0.0")
	parser.add_argument("-p", "--port", help="Listen port", type=int, default="8080")
	parser.add_argument("-c", "--config", help="Configuration file", default=None)
	parser.add_argument("--public", help="Run a public instance (Feeds and network sniffing disabled)", action="store_true", default=False)
	parser.add_argument("--max-workers", help="Number of worker processes to use (default 4)", type=int, default=4)
	parser.add_argument("--tls-proxy-port", help="Port number on which to start the TLS proxy on. No proxy started if not specified.", type=int, default=0)
	
	args = parser.parse_args()
	os.system('clear')
	sys.stderr.write("===== Malcom %s - Malware Communications Analyzer =====\n\n" % Malcom.config['VERSION'])

	if args.config:
		parse_config(args.config)
	else:
		Malcom.config['LISTEN_INTERFACE'] = args.interface
		Malcom.config['LISTEN_PORT'] = args.port
		Malcom.config['MAX_WORKERS'] = args.max_workers
		Malcom.config['PUBLIC'] = args.public
		Malcom.config['TLS_PROXY_PORT'] = args.tls_proxy_port
		Malcom.config['FEEDS'] = args.feeds
		Malcom.config['ANALYTICS'] = args.analytics

	sys.stderr.write("Detected interfaces:\n")
	for iface in Malcom.config['IFACES']:
		sys.stderr.write("%s:\t%s\n" % (iface, Malcom.config['IFACES'][iface]))
	
	Malcom.analytics_engine = Analytics()

	

################################################

# from Malcom.analytics.analytics import Analytics
# from Malcom.feeds.feed import FeedEngine
# from Malcom.web.webserver import MalcomWeb
# from Malcom.networking.tlsproxy.tlsproxy import MalcomTLSProxy
# from Malcom.networking import netsniffer

################################################

	if Malcom.config['SNIFFER']:
		sys.stderr.write("[+] Starting sniffer...\n")
		if Malcom.config['TLS_PROXY_PORT'] > 0:
			sys.stderr.write("[+] Starting TLS proxy on port %s\n" % Malcom.config['TLS_PROXY_PORT'])
			Malcom.tls_proxy = MalcomTLSProxy(Malcom.config['TLS_PROXY_PORT'])
			Malcom.tls_proxy.start()
		else:
			Malcom.tls_proxy = None
		from Malcom.networking.tlsproxy.tlsproxy import MalcomTLSProxy
		from Malcom.networking import netsniffer
		sys.stderr.write("Importing packet captures...\n")

		for s in Malcom.analytics_engine.data.get_sniffer_sessions():
			Malcom.sniffer_sessions[s['name']] = netsniffer.Sniffer(Malcom.analytics_engine, 
																	s['name'], 
																	None, 
																	None, 
																	filter_restore=s['filter'], 
																	intercept_tls=s['intercept_tls'] if Malcom.tls_proxy else False)
			Malcom.sniffer_sessions[s['name']].pcap = True


	# call malcom to run feeds - this will not start the web interface
	if Malcom.config['FEEDS']:
		sys.stderr.write("[+] Importing feeds...\n")
		from Malcom.feeds.feed import FeedEngine
		scheduler = Malcom.config['FEEDS_SCHEDULER']
		Malcom.feed_engine = FeedEngine(Malcom.analytics_engine, scheduler)
		Malcom.feed_engine.load_feeds()
		# launch process		

		if scheduler:
			Malcom.feed_engine.start()
			sys.stderr.write("Starting feed scheduler...\n")
		else:
			sys.stderr.write("Feed scheduler must be started manually.\n")

	# run analytics
	if Malcom.config['ANALYTICS']:
		sys.stderr.write("[+] Starting analytics engine...\n")
		Malcom.analytics_engine.start()
		
	if Malcom.config['WEB']:
		sys.stderr.write("[+] Starting webserver...\n")
		from Malcom.web.webserver import MalcomWeb
		Malcom.web = MalcomWeb(Malcom.config['PUBLIC'], Malcom.config['LISTEN_PORT'], Malcom.config['LISTEN_INTERFACE'])

	if Malcom.config['WEB']:
		Malcom.web.start_server()
	else:
		try:
			while True:
				raw_input()
		except KeyboardInterrupt, e:
			pass

	sys.stderr.write("\nExiting gracefully\n")
	
	if Malcom.config['WEB']:
		sys.stderr.write('Stopping webserver... ')
		sys.stderr.write("done.\n")

	if Malcom.config['ANALYTICS']:
		sys.stderr.write("Stopping analytics engine... ")
		Malcom.analytics_engine.stop()
		Malcom.analytics_engine.join()
		sys.stderr.write("done.\n")

	if Malcom.config['SNIFFER'] and len(Malcom.sniffer_sessions) > 0:
		sys.stderr.write('Stopping sniffing sessions... ')
		for s in Malcom.sniffer_sessions:
			session = Malcom.sniffer_sessions[s]
			session.stop()

	if Malcom.config['FEEDS']:
		sys.stderr.write("Stopping feed engine... ")
		Malcom.feed_engine.stop_all_feeds()
		sys.stderr.write("done.\n")

	if Malcom.config['TLS_PROXY_PORT']:
		sys.stderr.write("Stopping TLS proxy... ")
		Malcom.tls_proxy.stop()
		sys.stderr.write("done.\n")

	exit()
	