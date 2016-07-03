#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from core.web import webapp

logging.basicConfig(format='%(levelname)s:%(module)s:%(message)s', level=logging.ERROR)

if __name__ == '__main__':
    webapp.run(host="0.0.0.0")
