#!/usr/bin/env python
# -*- coding: utf-8 -*-

from core.feed import FeedEngine
import logging
import time

logging.basicConfig(format='%(levelname)s:%(module)s:%(message)s', level=logging.INFO)

if __name__ == '__main__':
    fe = FeedEngine()

    while True:
        time.sleep(1)
