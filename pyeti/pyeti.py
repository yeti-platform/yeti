import requests
import logging

class YetiApi(object):
    """Python class for interacting with the Yeti API"""

    def __init__(self, url, auth=tuple()):
        super(YetiApi, self).__init__()
        if not url.endswith('/'):
            url += "/"
        self.yeti_url = url
        self.auth = auth
        self._test_connection()

    def analysis_match(self, observables):
        json_payload = {"observables": observables}
        return self._make_post("analysis/match", json_payload)

    def observable_search(self, count=50, offset=1, regex=False, **kwargs):
        json_payload = {"filter": kwargs, "params": {"page": offset, "range": count, "regex": regex}}
        return self._make_post("observablesearch/", json_payload)

    def observable_details(self, id):
        return self._make_get("observable/{}".format(id))

    def observable_add(self, value, tags=[], context={}, source="API"):
        json_payload = {"tags": tags, "value": value, "source": source, "context": context}
        return self._make_post('observable/', payload=json_payload)

    def observable_bulk_add(self, observables, tags=[], source=None):
        json_payload = {"tags": tags, "observables": observables}
        if source:
            json_payload['source'] = source
        return self._make_post('observable/bulk', payload=json_payload)

    def _test_connection(self):
        if self._make_post("observablesearch/"):  # replace this with a more meaningful URL
            logging.debug("Connection to {} successful".format(self.yeti_url))
        else:
            logging.debug("Conncetion to {} failed".format(self.yeti_url))

    def _make_post(self, url, payload={}):
        return self._make_request(url, method="POST", payload=payload)

    def _make_get(self, url):
        return self._make_request(url)

    def _make_request(self, url, method="GET", payload={}):
        url = "{}{}".format(self.yeti_url, url)
        if method == "POST":
            r = requests.post(url, headers={'Accept': 'application/json'}, auth=self.auth, json=payload)
        else:
            r = requests.get(url, auth=self.auth)

        if r.status_code == 200:
            logging.debug("Success ({})".format(r.status_code))
            return r.json()
        else:
            logging.error("An error occurred ({}): {}".format(r.status_code, url))


if __name__ == '__main__':
    y = YetiApi(url='http://localhost:5000/api/')
    print y.observable_add('asdoiajwdoiawjd.com', ['asd'])
