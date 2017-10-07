Extending Yeti
==============

Yeti can be extended to suit most use-cases. Extension is usually made via three vectors:

* **Feeds**: Your basic data source. Feeds can be customized to automatically collect and processes external data.
* **Analytics**: Analytics are meant to enrich data that is already present in the database. Extract hostnames from URLs, resolve hostnames, etc.
* **Exports**: The way Yeti disseminates data. Exports use templates to format and export data that may be consumed by proxy appliances, scripts, etc.


Feeds
-----

Feeds are Yeti's main way of automatically collecting and parsing data into searchable objects. These can be Observables (URLs, IP addresses, hashes, etc.), Indicators (regular expressions, Yara rules), or Entities (Exploit Kits, Malware, etc.).

The most common use-case for Feeds is to quickly and regularly import large amounts of Observables or Indicatos from various sources.


.. _creating-feed:

Creating feeds
^^^^^^^^^^^^^^

Creating a feed is pretty straightforward. Yeti will recursively load all :class:`core.feed.Feed` objects defined in the ``/plugins/feed/`` directory.

New feeds need to have ``default_values`` attribute which sets some of the necessary fields (see the class attributes for details).

* **frequency**: A ``timedelta`` field designating the delta between runs.
* **name**: The name of the feed.
* **source**: The URL which the feed will use to query data.
* **description**: A short description of the feed.

For example, in the :class:``ZeusTrackerConfigs`` feed, the class is defined as follows::

    class ZeusTrackerConfigs(Feed):

        default_values = {
            "frequency": timedelta(hours=1),
            "name": "ZeusTrackerConfigs",
            "source": "https://zeustracker.abuse.ch/monitor.php?urlfeed=configs",
            "description": "This feed shows the latest 50 ZeuS config URLs.",
        }

After that, two functions need to be created: :func:`core.feed.Feed.update` and :func:`core.feed.Feed.analyze`. The goal of the ``update`` function is to fetch the remote data, and the goal of ``analyze`` is to parse it and translate it into Observables, Indicators, or Entities that Yeti can store and later analyze.

``ZeusTrackerConfigs``'s update function looks like this::

    def update(self):
          for d in self.update_xml('item', ["title", "link", "description", "guid"]):
              self.analyze(d)

See how the :func:`core.feed.Feed.update_xml` helper is used. Since the ``source`` URL returns XML data, ``update_xml`` will know how to parse it and produce python dictionaries that can then be passed to the :func:`core.feed.Feed.analyze` function::

    def analyze(self, dict):
          url_string = re.search(r"URL: (?P<url>\S+),", dict['description']).group('url')

          context = {}
          date_string = re.search(r"\((?P<date>[0-9\-]+)\)", dict['title']).group('date')
          context['date_added'] = datetime.strptime(date_string, "%Y-%m-%d")
          context['status'] = re.search(r"status: (?P<status>[^,]+)", dict['description']).group('status')
          context['version'] = int(re.search(r"version: (?P<version>[^,]+)", dict['description']).group('version'))
          context['guid'] = dict['guid']
          context['source'] = self.name
          try:
              context['md5'] = re.search(r"MD5 hash: (?P<md5>[a-f0-9]+)", dict['description']).group('md5')
          except AttributeError as e:
              pass

          try:
              n = Url.get_or_create(value=url_string)
              n.add_context(context)
              n.add_source("feed")
              n.tag(['zeus', 'c2', 'banker', 'crimeware', 'malware'])
          except ObservableValidationError as e:
              logging.error(e)

Here some pretty basic parsing using regular expressions is being done. Since the parsing is done using Python code, feeds can parse virtually any data in any format.

To avoid having to deal with duplicate elements, the use of :func:`core.observables.Observable.get_or_create`, :func:`core.indicators.Indicator.get_or_create` or :func:`core.entities.Entity.get_or_create` is recommended.

Context, tags, and sources can also be added to Observables. To do so, use the  :func:`core.observables.Observable.add_context`, :func:`core.observables.Observable.tag`, or :func:`core.observables.Observable.add_source` accordingly.


Testing feeds
^^^^^^^^^^^^^

Before pushing a feed into production, it is recommended to test them with the simple script ``testfeeds.py``::

    $ python testfeeds.py ZeusTrackerConfigs
    Running ZeusTrackerConfigs...
    ZeusTrackerConfigs: success!

Any raised exception will be displayed.


Pushing into production
^^^^^^^^^^^^^^^^^^^^^^^

Once the feed is in its corresponding directory, it will show up in the URL ``/dataflows``. Any errors raised by the feeds will show up here. Feeds can also be individually refreshed or toggled. A green row confirms that your feed is up and running!


Contributing
------------

Want to contribute? Awesome! Please follow the instructions in `contrib <https://github.com/yeti-platform/yeti/tree/master/contrib/>`_ to make sure everything goes smoothly.
