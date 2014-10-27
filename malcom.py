#!/usr/bin/env python
# -*- coding: utf-8 -*-

__description__ = 'Malcom - Malware communications analyzer'
__author__ = '@tomchop_'
__version__ = '1.2 alpha'
__license__ = "GPL"

import os, sys, argparse
import netifaces as ni

from Malcom.config.malconf import MalcomSetup
from Malcom.auxiliary.toolbox import debug_output

setup = MalcomSetup()

# this should be stored and loaded from a configuration file

# malconf['DEBUG'] = True
# malconf['VERSION'] = "1.2 alpha"

# malconf['LISTEN_INTERFACE'] = "0.0.0.0"
# malconf['LISTEN_PORT'] = 8080
# malconf['MAX_WORKERS'] = 4
# malconf['PUBLIC'] = False
# malconf['TLS_PROXY_PORT'] = False
# malconf['FEEDS'] = False
# malconf['ANALYTICS'] = False

# malconf['BASE_PATH'] = os.getcwd() + '/Malcom'
# malconf['SNIFFER_DIR'] = malconf['BASE_PATH'] + '/sniffer'
# malconf['FEEDS_DIR'] = malconf['BASE_PATH'] + '/feeds'

# malconf['IFACES'] = {}


setup = MalcomSetup()
setup['VERSION'] = "1.2a"

if __name__ == "__main__":

	# Init
	os.system('clear')
	sys.stderr.write("===== Malcom %s - Malware Communications Analyzer =====\n\n" % setup['VERSION'])

	parser = argparse.ArgumentParser(description="Malcom - malware communications analyzer")
	parser.add_argument("-c", "--config", help="Configuration file", default=None)
	parser.add_argument("-a", "--analytics", help="Run analytics", action="store_true", default=False)
	parser.add_argument("-f", "--feeds", help="Run feeds", action="store_true", default=False)
	parser.add_argument("-i", "--interface", help="Listen interface for webserver", default="0.0.0.0")
	parser.add_argument("-p", "--port", help="Listen port for webserver", type=int, default="8080")
	parser.add_argument("-s", "--sniffer", help="Start sniffer", action="store_true", default=True)
	parser.add_argument("--public", help="Run a public instance (Feeds and network sniffing disabled)", action="store_true", default=False)
	parser.add_argument("--max-workers", help="Number of worker processes to use (default 4)", type=int, default=4)
	parser.add_argument("--tls-proxy-port", help="Port number on which to start the TLS proxy on. No proxy started if not specified.", type=int, default=0)
	
	args = parser.parse_args()

	setup.load_config(args)

	# detect interfaces
	sys.stderr.write("Detected interfaces:\n")

	for iface in setup['IFACES']:
		sys.stderr.write("%s:\t%s\n" % (iface, setup['IFACES'][iface]))
	
################################################

# from Malcom.analytics.analytics import Analytics
# from Malcom.feeds.feed import FeedEngine
# from Malcom.web.webserver import MalcomWeb
# from Malcom.networking.tlsproxy.tlsproxy import MalcomTLSProxy
# from Malcom.networking import netsniffer

################################################
	if setup['SNIFFER']:
		from Malcom.networking import netsniffer
		yara_rules = setup.get("YARA_PATH", None)
		setup.sniffer_engine = netsniffer.SnifferEngine(setup, yara_rules=yara_rules)

		
	# call malcom to run feeds - this will not start the web interface
	if setup['FEEDS']:
		sys.stderr.write("[+] Importing feeds...\n")
		from Malcom.feeds.feed import FeedEngine
		setup.feed_engine = FeedEngine(setup)
		try:
			loaded = setup.feed_engine.load_feeds(setup['ACTIVATED_FEEDS'])
		except Exception, e:
			sys.stderr.write("Could not load feeds specified in feeds_dir: %s\n" % e)
			exit()
		
		# launch process		
		if setup['FEEDS_SCHEDULER']:
			setup.feed_engine.scheduler = True
			("Starting feed scheduler...\n")
		else:
			setup.feed_engine.scheduler = False
			sys.stderr.write("[!] Feed scheduler must be started manually.\n")

		setup.feed_engine.period = 1
		setup.feed_engine.start()

	# run analytics
	if setup['ANALYTICS']:
		sys.stderr.write("[+] Starting analytics engine...\n")
		from Malcom.analytics.analytics import Analytics
		setup.analytics_engine = Analytics(setup['MAX_WORKERS'])
		setup.analytics_engine.start()
		
	if setup['WEB']:
		sys.stderr.write("[+] Starting webserver...\n")
		from Malcom.web.webserver import MalcomWeb
		setup.web = MalcomWeb(setup['AUTH'], setup['LISTEN_PORT'], setup['LISTEN_INTERFACE'], setup)

	if setup['WEB']:
		setup.web.start_server()
	else:
		try:
			while True:
				raw_input()
		except KeyboardInterrupt, e:
			pass

	sys.stderr.write("\nExiting gracefully\n")
	
	if setup['WEB']:
		sys.stderr.write('[.] Stopping webserver... ')
		sys.stderr.write("done.\n")

	if setup['ANALYTICS']:
		sys.stderr.write("[.] Stopping analytics engine... ")
		setup.analytics_engine.terminate()
		sys.stderr.write("done.\n")

	if setup['SNIFFER'] and len(setup.sniffer_engine.sessions) > 0:
		sys.stderr.write('[.] Stopping sniffing sessions... ')
		for s in setup.sniffer_engine.sessions:
			session = setup.sniffer_engine.sessions[s]
			session.stop()
		sys.stderr.write("done.\n")

	if setup['FEEDS']:
		sys.stderr.write("[.] Stopping feed engine... ")
		setup.feed_engine.terminate()
		sys.stderr.write("done.\n")

	if setup['TLS_PROXY_PORT']:
		sys.stderr.write("[.] Stopping TLS proxy... ")
		setup.sniffer_engine.tls_proxy.stop()
		sys.stderr.write("done.\n")

	exit()
	