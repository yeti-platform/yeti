# Yeti - Your everyday threat intelligence

* [What is Yeti?](#what-is-yeti)
* [Installation](#installation)
* [Docker images](#docker-images)
* [Useful links](#useful-links)

## What is Yeti?

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

## Installation

There's are a few handy bootstrap scripts in [/extras](https://github.com/yeti-platform/yeti/tree/master/extras) that you can use to install a production instance of Yeti.

If you're really in a hurry, you can `curl | bash` them.

    $ curl https://raw.githubusercontent.com/yeti-platform/yeti/master/extras/ubuntu_bootstrap.sh | sudo /bin/bash

Please refer to the [full documentation](http://yeti-platform.readthedocs.io/en/latest/installation.html) for more detailed steps.

## Docker images

Yeti has a `docker-compose` script to get up and running even faster; this is useful for testing or even running production instances of Yeti should your infrastructure support it. Full instructions [here](https://github.com/yeti-platform/yeti/tree/master/extras/docker), but in a nutshell:

    $ git clone https://github.com/yeti-platform
    $ cd yeti/extras/docker
    $ docker-compose up

## Useful links

  * [Documentation](http://yeti-platform.readthedocs.io/en/latest/)
  * [Yeti users mailing list](https://groups.google.com/forum/#!forum/yeti-users)
  * [Project website & blog](https://yeti-platform.github.io)
  * [Installation](http://yeti-platform.readthedocs.io/en/latest/installation.html)
  * [Getting started](http://yeti-platform.readthedocs.io/en/latest/getting-started.html)
