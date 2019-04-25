# Author: Chen Erlich
# YETI Version: 1
# Elastic Stack Version: 6.7

import logging
import time

from logging.handlers import RotatingFileHandler
from bson.json_util import DEFAULT_JSON_OPTIONS
from pymongo import MongoClient
from bson import json_util
from datetime import datetime
from elasticsearch import Elasticsearch
from pymongo.errors import CursorNotFound, AutoReconnect
from ssl import SSLWantReadError


# Logging config
def set_logging():
    global logger

    logging.basicConfig(format='%(asctime)s - %(lineno)d - %(funcName)s - %(levelname)s - %(message)s',
                        level=logging.INFO)
    DEFAULT_JSON_OPTIONS.datetime_representation = 2

    logger = logging.getLogger("yeti_to_elastic")

    formatter = logging.Formatter('%(asctime)s - %(lineno)d - %(funcName)s - %(levelname)s - %(message)s')

    # You may change here the path for the log file
    handler = RotatingFileHandler('yeti_to_elastic.log', maxBytes=20000, backupCount=5)
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    logger.addHandler(handler)


class YetiFeedSender(object):

    def __init__(self, elastic_index, excluded_feeds=set(), mongo_client=None, mongo_hostname="localhost",
                 elastic_instance=None, elastic_hostname=None, elastic_port=9200, elastic_user=None, elastic_pass=None,
                 elastic_use_ssl=None, elastic_verify_certs=None):
        """
            This class connects to YETI's MongoDB and to Elasticsearch.
            It parses the observable collection in YETI's MongoDB and sends to Elasticsearch.
        :param elastic_index: Elasticsearch index name.
        :param excluded_feeds: Set that includes feeds to exclude from indexing.
        :param mongo_client: Mongodb client.
        :param mongo_hostname: Mongodb hostname.
        :param elastic_instance: Elasticsearch connection instance.
        :param elastic_hostname: Elasticsearch hostname.
        :param elastic_port: Elasticsearch indexing port.
        :param elastic_user: Elasticsearch user.
        :param elastic_pass: Elasticsearch password.
        :param elastic_use_ssl: Boolean. Use SSL flag.
        :param elastic_verify_certs: Boolean. Verify certificate flag.
        """

        self.elastic_index = elastic_index
        self.excluded_feeds = excluded_feeds

        if mongo_client:
            self.mongo_client = mongo_client
        else:
            mongo_hostname = mongo_hostname
            self.create_mongo_connection(mongo_hostname)

        if elastic_instance:
            self.elastic_instance = elastic_instance
        else:
            elastic_hostname = elastic_hostname
            elastic_port = elastic_port
            elastic_user = elastic_user
            elastic_pass = elastic_pass
            elastic_use_ssl = elastic_use_ssl
            elastic_verify_certs = elastic_verify_certs

            self.create_elastic_connection(elastic_hostname, elastic_port, use_ssl=elastic_use_ssl,
                                           verify_certs=elastic_verify_certs, username=elastic_user,
                                           password=elastic_pass)

    def create_mongo_connection(self, hostname="localhost"):
        """
            Creates a connection to YETI's mongo DB.
        :param hostname: Hostname to connect to. Default is "localhost"
        :return: None
        """

        self.mongo_client = MongoClient('mongodb://{}:27017/'.format(hostname))

    def create_elastic_connection(self, hostname, port, use_ssl=True, verify_certs=False, username=None, password=None):
        """
            Creates an Elasticsearch connection.
        :param hostname: Elasticsearch hostname/ip address
        :param port: Elasticsearch indexing port
        :param use_ssl: Is the server uses ssl or not
        :param verify_certs: Should the request verify the certification
        :param username: Username in order to connect to Elasticsearch
        :param password: Password in order to connect to Elasticsearch
        :return: None
        """

        if username and password:
            if use_ssl:
                self.elastic_instance = Elasticsearch(
                    hosts=[{'host': hostname, 'port': port}],
                    http_auth=(username, password),
                    use_ssl=use_ssl,
                    verify_certs=verify_certs)
            else:
                self.elastic_instance = Elasticsearch(hosts=[{'host': hostname, 'port': port}],
                                                      http_auth=(username, password))
        else:
            if use_ssl:
                self.elastic_instance = Elasticsearch(hosts=[{'host': hostname, 'port': port}],
                                                      use_ssl=use_ssl,
                                                      verify_certs=verify_certs)
            else:
                self.elastic_instance = Elasticsearch(hosts=[{'host': hostname, 'port': port}])

    @staticmethod
    def format_observable(observable, excluded_feeds=()):
        """
            Formats an observable to Elasticsearch accepted structure
        :param observable: observable dict
        :param excluded_feeds: excluded_feeds set
        :return: deserialized_json str
        """

        formatted_dict = dict()
        formatted_dict["@timestamp"] = datetime.now().isoformat()

        # Loop observable dictionary
        for key in observable.keys():
            if key == "_id":
                formatted_dict["id_generation_time"] = observable[key].generation_time.isoformat()
            elif key == "parsed_url":
                for parsed_url_key in observable[key].keys():
                    formatted_dict["parsed_url.{}".format(parsed_url_key)] = observable[key][parsed_url_key]
            elif key == "created":
                formatted_dict["created"] = observable[key].isoformat()
            elif key == "_cls":
                formatted_dict["cls"] = observable[key]
            elif key == "tags":
                index = 0
                while index < len(observable[key]):
                    observable[key][index]["first_seen"] = observable[key][index]["first_seen"].isoformat()
                    observable[key][index]["last_seen"] = observable[key][index]["last_seen"].isoformat()
                    index += 1
                formatted_dict[key] = observable[key]
            elif key == "last_tagged":
                formatted_dict[key] = observable[key].isoformat()
            elif key == "context":
                for context_entry_dict in observable[key]:

                    if context_entry_dict["source"] in excluded_feeds:
                        observable[key].remove(context_entry_dict)

                # If we excluded all feeds, return an empty string
                if not observable[key]:
                    logger.warning("The value: {} from the date {} was not indexed".format(observable["value"],
                                                                                           formatted_dict["created"]))
                    return ''

                formatted_dict[key] = observable[key]
            else:

                # Check for doc values of FILES.
                # If it's a FILE, remove the "FILE:" prefix from the value
                if key == "value" and str(observable[key]).startswith("FILE:"):
                    observable[key] = observable[key][5:]

                formatted_dict[key] = observable[key]

        # Format the dict to json. Supports mongodb structure representation
        json_to_elastic = json_util.dumps(formatted_dict)

        return json_to_elastic

    def extract_and_send(self, elastic_index=None):
        """
            This method extracts data out of the mongodb and sends in to elasticsearch.
        :param elastic_index: Used if there is a need to change the elastic index
        :return: None
        """

        if elastic_index:
            self.elastic_index = elastic_index

        db = self.mongo_client.yeti
        observables = db.observable

        response = ''
        processed = 0

        while True:
            try:

                # Loop observables
                for observable in observables.find(no_cursor_timeout=True).skip(processed):

                    processed += 1
                    json_to_index = self.format_observable(observable, excluded_feeds=self.excluded_feeds)

                    # If the json to index is empty, don't index
                    if not json_to_index:
                        continue

                    try:

                        # Index to elasticsearch
                        response = self.elastic_instance.index(index=self.elastic_index, doc_type="yeti_feed",
                                                               id=observable.get("_id"),
                                                               body=json_to_index,
                                                               request_timeout=30)
                    except TypeError as type_error:
                        logger.warning(type_error)
                    except SSLWantReadError as ssl_error:
                        logger.error(ssl_error)
                    except Exception as e:
                        logger.error(str(e))

                    if response.get("result") == "created":
                        logger.info(
                            "Created {} in index {} - Processed: {}".format(response.get("_id"), self.elastic_index,
                                                                            processed))
                    elif response.get("result") == "updated":
                        logger.info(
                            "Updated {} in index {} - Processed: {}".format(response.get("_id"), self.elastic_index,
                                                                            processed))
                    else:
                        logger.warning(
                            "Failed to index {} in index {} - Processed: {}".format(response.get("_id"),
                                                                                    self.elastic_index,
                                                                                    processed))

                logger.info("Finished processing all events. Sleeping for 30 seconds.")
                time.sleep(30)

            except CursorNotFound:
                logger.warning("Lost cursor. Retry with skip")
            except AutoReconnect as e:
                logger.error("Connection Error: " + str(e))
            except Exception as e:
                logger.error("Unknown Error: {}".format(str(e)))


if __name__ == '__main__':
    sender = YetiFeedSender("yeti-feeds", elastic_hostname="<elastic_hostname>")
    sender.extract_and_send()

    """
    Example:
        sender = YetiFeedSender("yeti-feeds", elastic_hostname="<elastic_hostname>"
                                excluded_feeds=("AsproxTracker"),
                                elastic_port=<elasticsearch_port_to_index>)
        sender.extract_and_send()
    """
