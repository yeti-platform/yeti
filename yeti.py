#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from core.web import webapp

logging.basicConfig(format='%(levelname)s:%(module)s:%(message)s', level=logging.ERROR)

if __name__ == '__main__':
    print "[+] Yeti started. Point browser to http://localhost:5000/"
    webapp.run(host="0.0.0.0")
