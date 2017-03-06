import requests
import logging

class YetiApi(object):
    """Python class for interacting with the Yeti API"""

    def __init__(self, url, auth=tuple(), api_key=None):
        super(YetiApi, self).__init__()
        if not url.endswith('/'):
            url += "/"
        self.yeti_url = url
        self.auth = auth
        self.api_key = api_key
        self._test_connection()

    def analysis_match(self, observables):
        """Matches a list of observables against Yeti indicators.

        Args:
            observables: An array of strings representing observables

        Returns:
            JSON representation of match response.
        """
        json_payload = {"observables": observables}
        return self._make_post("analysis/match", json_payload)

    def observable_search(self, count=50, offset=1, regex=False, **kwargs):
        """Search for observables.

        Args:
            count: How many Observables you want to fetch.
            offset: How many sets of *count* Observables you want to skip
                    (total skipped = offset * count)
            regex: Use regular expressions to Search.
            kwargs: Remaining keyword arguments will be transformed in a JSON
                    object that will act as the filter.

        Returns:
            Array of JSON representations of matching Observables.
        """
        json_payload = {"filter": kwargs, "params": {"page": offset, "range": count, "regex": regex}}
        return self._make_post("observablesearch/", json_payload)

    def observable_details(self, id):
        """Get details on an Observable.
        Args:
            id: A string representing the observable's ObjectID

        Returns:
            JSON representation of the requested Observable.
        """
        return self._make_get("observable/{}".format(id))

    def observable_add(self, value, tags=[], context={}, source="API"):
        """Add an observable to the dataset

        Args:
            value: the Observable value
            tags: An array of strings representing tags
            context: A dictionary object with context information
            source: A string representing the source of the data. Defaults to
                    "API".

        Returns:
            JSON representation of the created observable.
        """
        json_payload = {"tags": tags,
                        "value": value,
                        "source": source,
                        "context": context}
        return self._make_post('observable/', payload=json_payload)

    def observable_bulk_add(self, observables, tags=[]):
        """Add an observable to the dataset

        Args:
            value: the Observable value
            tags: An array of strings representing tags
            context: A dictionary object with context information
            source: A string representing the source of the data. Defaults to
                    "API".

        Returns:
            JSON representation of the created observable.
        """
        json_payload = {"tags": tags, "observables": observables}
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

        headers = {}
        if self.api_key:
            headers.update({"X-Api-Key": self.api_key})

        if method == "POST":
            headers.update({'Accept': 'application/json'})
            r = requests.post(url, headers=headers, auth=self.auth, json=payload)
        else:
            r = requests.get(url, auth=self.auth, headers=headers)

        if r.status_code == 200:
            logging.debug("Success ({})".format(r.status_code))
            return r.json()
        else:
            logging.error("An error occurred ({}): {}".format(r.status_code, url))


if __name__ == '__main__':
    y = YetiApi(url='http://localhost:5000/api/')
    print y.observable_add('asdoiajwdoiawjd.com', ['asd'])
