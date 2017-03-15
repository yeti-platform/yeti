# Yeti - Your everyday threat intelligence

**Useful links**

* [Documentation](http://yeti-platform.readthedocs.io/en/latest/)
* [Project website & blog](https://yeti-platform.github.io)

## What is this?

Yeti is a platform meant to organize observables, indicators of compromise,
TTPs, and knowledge on threats in a single, unified repository. Yeti will also
automatically enrich observables (e.g. resolve domains, geolocate IPs) so that
you don't have to. Yeti provides an interface for humans (shiny Bootstrap-based
UI) and one for machines (web API) so that your other tools can talk nicely to
it.

Yeti was born out of frustration of having to answer the question "where have
I seen this artifact before?" or Googling shady domains to tie them to a
malware family.

In a nutshell, Yeti allows you to:

* Submit observables and get a pretty good guess on the nature of the threat.
* Inversely, focus on a threat and quickly list all TTPs, Observables, and
  associated malware.
* Let responders skip the "Google the artifact" stage of incident response.
* Let analysts focus on adding intelligence rather than worrying about
  machine-readable export formats.
* Visualize relationship graphs between different threats.

This is done by:

* Collecting and processing observables from a wide array of different sources
  (MISP instances, malware trackers, XML feeds, JSON feeds...)
* Providing a web API to automate queries (think incident management platform)
  and enrichment (think malware sandbox).
* Export the data in user-defined formats so that they can be ingested by
  third-party applications (think blocklists, SIEM).

## Quick & dirty install

Please refer to the [full documentation](http://yeti-platform.readthedocs.io/en/latest/installation.html) for more detailed steps.

Install dependencies:

    $ sudo apt-get install build-essential git python-dev python-pip
    redis-server mongodb libxml2-dev libxslt-dev zlib1g-dev python-virtualenv

Activate virtualenv, then install requirements:

    $ pip install -r requirements.txt

Start the web UI (will spawn a HTTP server on ``http://localhost:5000``):

    $ ./yeti.py

This will only enable the web interface - if you want to use Feeds and Analytics, you'll be better off starting the workers as well:

    $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q exports -n exports -Ofair -c 2 --purge
    $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q feeds -n feeds -Ofair -c 2 --purge
    $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q analytics -n analytics -Ofair -c 2 --purge
    $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q oneshot -n oneshot -c 2 --purge
    $ celery -A core.config.celeryctl beat -S core.scheduling.Scheduler --loglevel=ERROR
