.. YETI documentation master file, created by
   sphinx-quickstart on Thu Apr 14 17:47:32 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to YETI's documentation!
================================

**Useful links**

* `Project website & blog <https://yeti-platform.github.io/>`_
* `Yeti Users mailing list <https://groups.google.com/forum/#!forum/yeti-users>`_
* `Code repository <https://github.com/yeti-platform/yeti>`_
* `Installation <http://yeti-platform.readthedocs.io/en/latest/installation.html>`_
* `Getting started <http://yeti-platform.readthedocs.io/en/latest/getting-started.html>`_

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

Contents:
---------

.. toctree::
  installation
  use-cases
  objects
  extending
  api
