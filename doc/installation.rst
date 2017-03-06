.. _installation:

Installation
============

Installing Yeti is pretty straightforward. This procedure was tested on Ubuntu 15.04, but YMMV.

Install dependencies::

  $ sudo apt-get install build-essential git python-dev mongodb redis libxml2-dev libxslt-dev zlib1g-dev python-virtualenv

Activate virtualenv if you want to, then ``pip install`` requirements::

  $ [sudo] pip install -r requirements.txt


Quick & dirty
-------------

Start the web UI (will spawn a HTTP server on ``http://localhost:5000``)::

  $ ./yeti.py

This will only enable the web interface - if you want to use Feeds and Analytics, you'll be better off starting the workers as well::

  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Ofair -c 2 -Q feeds -n feeds --purge
  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -c 2 -Q oneshot -n oneshot --purge
  $ celery -A core.config.celeryctl.celery_app worker --loglevel=ERROR -Ofair -c 2 --purge
  $ celery -A core.config.celeryctl beat -S core.scheduling.Scheduler --loglevel=ERROR



Production use
--------------

For production use, it may be better to daemonize Yeti and tweak redis for performance.

Start off with::

  $ sudo apt-get install nginx uwsgi

systemd protips::

  $ sudo service yeti_web start|stop|restart
  or
  $ sudo systemctl start|status|stop yeti_web

To enable the systemd scripts once you've installed them::

  sudo systemctl enable yeti_web


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


Web interface & API
^^^^^^^^^^^^^^^^^^^

File ``/lib/systemd/system/yeti_web.service``::

  [Unit]
  Description=Yeti web servers
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bash -c "source /home/user/env-yeti/bin/activate; cd /home/user/yeti; python yeti.py"

  [Install]
  WantedBy=multi-user.target



Or if you want to use using UWSGI (taken from http://uwsgi-docs.readthedocs.io/en/latest/Systemd.html)::

  [Unit]
  Description=Yeti UWSGI server
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bach -c "source /home/user/env-yeti/bin/activate; cd /home/user/yeti; uwsgi --socket 127.0.0.1:8000 -w yeti --callable webapp --processes 4 --threads 2 --stats 127.0.0.1:9191"
  Restart=always
  KillSignal=SIGQUIT
  Type=notify
  StandardError=syslog
  NotifyAccess=all

  [Install]
  WantedBy=multi-user.target

For this to work, you'll need to have an nginx configuration like the following one::

  server {
      listen 80;
      server_name yeti;

      location / {
          include uwsgi_params;
          uwsgi_pass 127.0.0.1:8000;
      }
  }

Replace the ``listen`` and ``server_name`` directives as you see fit.

Oneshot analytics
^^^^^^^^^^^^^^^^^^

File - ``/lib/systemd/system/yeti_oneshot.service``::

  [Unit]
  Description=Yeti workers - Oneshot
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bash -c "source /home/user/env-yeti/bin/activate; cd /home/user/yeti; celery -A core.config.celeryctl.celery_app worker -c 4 -Q oneshot -n oneshot --purge"

  [Install]
  WantedBy=multi-user.target

Feeds
^^^^^

File - ``/lib/systemd/system/yeti_feeds.service``::

  [Unit]
  Description=Yeti workers - Feeds
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bash -c "source /home/cert/env-yeti/bin/activate; cd /home/cert/yeti; celery -A core.config.celeryctl.celery_app worker -Ofair -c 8 -Q feeds -n feeds --purge

  [Install]
  WantedBy=multi-user.target

Exports
^^^^^^^

File - ``/lib/systemd/system/yeti_feeds.service``::

  [Unit]
  Description=Yeti workers - Feeds
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bash -c "source /home/cert/env-yeti/bin/activate; cd /home/cert/yeti; celery -A core.config.celeryctl.celery_app worker -Ofair -c 8 -Q exports -n exports --purge

  [Install]
  WantedBy=multi-user.target


Analytics
^^^^^^^^^

File - ``/lib/systemd/system/yeti_analytics.service``::

  [Unit]
  Description=Yeti workers - Analytics
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bash -c "source /home/user/env-yeti/bin/activate; cd /home/user/yeti; celery -A core.config.celeryctl.celery_app worker -Ofair -c 10 --purge -Q analytics -n analytics"

  [Install]
  WantedBy=multi-user.target


Scheduler
^^^^^^^^^

File - ``/lib/systemd/system/yeti_beat.service``::

  [Unit]
  Description=Yeti beat scheduler
  After=mongodb.service redis.service

  [Service]
  Type=simple
  User=user
  ExecStart=/bin/bash -c "source /home/user/env-yeti/bin/activate; cd /home/user/yeti; celery -A core.config.celeryctl beat -S core.scheduling.Scheduler"

  [Install]
  WantedBy=multi-user.target
