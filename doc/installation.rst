.. _installation:

Installation
============

Installing Yeti is pretty straightforward. This procedure was tested on Ubuntu 16.04, but YMMV.

Install dependencies::

  $ sudo apt-get install build-essential git python-dev mongodb redis-server libxml2-dev libxslt-dev zlib1g-dev python-virtualenv

Download Yeti:

  $ git clone https://github.com/yeti-platform/yeti.git

Activate virtualenv if you want to, then ``pip install`` requirements::

  $ [sudo] pip install -r yeti/requirements.txt


Quick & dirty
-------------

Start the web UI (will spawn a HTTP server on ``http://localhost:5000``)::

  $ ./yeti.py

This will only enable the web interface - if you want to use Feeds and Analytics, you'll be better off starting the workers as well::

  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q exports -n exports -Ofair -c 2 --purge
  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q feeds -n feeds -Ofair -c 2 --purge
  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q analytics -n analytics -Ofair -c 2 --purge
  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Q oneshot -n oneshot -c 2 --purge
  $ celery -A core.config.celeryctl beat -S core.scheduling.Scheduler --loglevel=ERROR

Or, to bootstrap a production use instance of yeti (without the Redis tweaks), everyone's favorite command::

  $ curl https://raw.githubusercontent.com/yeti-platform/yeti/master/extras/bootstrap.sh | sudo /bin/bash

Production use
--------------

For production use, it may be better to daemonize Yeti and tweak redis for performance.

Install ``nginx`` and ``uwsgi``::

  $ sudo apt-get install nginx uwsgi

Optimize redis
^^^^^^^^^^^^^^

Some optimizations for redis (taken from `here <https://www.techandme.se/performance-tips-for-redis-cache-server/>`_):

Add the following lines in ``/etc/sysctl.conf``::

  # redis tweak
  vm.overcommit_memory = 1

Add the following lines in ``/etc/rc.local``::

  # disable transparent huge pages (redis tweak)
  See here for details: https://docs.mongodb.com/manual/tutorial/transparent-huge-pages/
  # increase max connections
  echo 65535 > /proc/sys/net/core/somaxconn or (sysctl -w net.core.somaxconn=65535)
  exit 0

Install systemd services
^^^^^^^^^^^^^^^^^^^^^^^^

Copy all files in ``extras/systemd/*`` to ``/lib/systemd/system/``. If you'd
rather have the web content served through nginx (recommended for production),
copy ``yeti_uwsgi.service``, otherwise you'll be fine with ``yeti_web.service``.

Enable the scripts with::

  $ sudo systemctl enable yeti_<SERVICENAME>.service

And start with::

  $ sudo systemctl start yeti_<SERVICENAME>.service

systemd protips::

    $ sudo service yeti_web start|stop|restart
    or
    $ sudo systemctl start|status|stop yeti_web

To enable the systemd scripts once you've installed them::

    sudo systemctl enable yeti_web

If you're running nginx, add the following configuraiton to one of the nginx
server directives::

  server {
      listen 80;
      server_name yeti;

      location / {
          include uwsgi_params;
          uwsgi_pass 127.0.0.1:8000;
      }
  }

Replace the ``listen`` and ``server_name`` directives as you see fit.
