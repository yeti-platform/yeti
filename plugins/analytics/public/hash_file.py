from datetime import timedelta
import re
import logging
import hashlib

from core.analytics import ScheduledAnalytics
from core.database import Link
from core.observables import Hash

HASH_TYPES_DICT = {'md5': hashlib.md5,
                   'sha1': hashlib.sha1,
                   'sha256': hashlib.sha256,
                   'sha512': hashlib.sha512}


class HashFile(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "HashFile",
        "description": "Extracts MD5, SHA1, SHA256, SHA512 hashes from file",
    }

    ACTS_ON = 'File'
    EXPIRATION = None  # only run this once

    @staticmethod
    def each(f):
        if f.body:
            for hash_type, h in HashFile.extract_hashes(f.body.contents):
                h = Hash.get_or_create(value=h.hexdigest())
                h.add_source("analytics")
                h.save()
                f.active_link_to(h, has_type, "HashFile", clean_old=False)

    @staticmethod
    def extract_hashes(body_contents):
        hashes = []
        hashers = {k: HASH_TYPES_DICT[k]() for k in HASH_TYPES_DICT}

        while True:
            chunk = body_contents.read(512*16)
            if not chunk:
                break
            for h in hashers.itervalues():
                h.update(chunk)

        return hashers.items()
