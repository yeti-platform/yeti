YETI quick start
=======

* **HowTo**: How to quickly start with YETI

How to add plugins
------------------

Plugins to work on data(observables)
    * Plugins should be placed in: **plugins/analytics/(public|private)/**
    * The observable types can be found in **core/observables/**
    * **Example:** MacAddress, Hash, Url, Ip, Hash, Hostname, Email, Bitcoint, etc::

Can be imported using::

    from core.observables import Hash, Url, Hostname, Ip, MacAddress, Email

How to check observable type, for example Ip::

  if isinstance(observable, Ip):


How to extract iocs/observables from text::

  from core.observables import Observable
  observables = Observable.from_string(text)
  
How to access config data::
  
  from core.config.config import yeti_config
  example: yeti_config.redis.host

Extend web api
------------------

Place your .py, use use redis_api.py as example in::

  core/web/api/redis_api.py

Add import and register to: **core/web/api/api.py**::

  from core.web.api.redis_api import ManageRedisData
  ManageRedisData.register(api)
  # you can use render to render html or render_json, for raw responses

How to check if all **services** running correctly
------------------------------------------------

* Service state should be **running** not loaded::

  "systemctl status yeti_*"
  
Logging
------------------------------------------------

All the logging by default can be find in **/var/log/syslog**::

  tail -f /var/log/syslog
  
You can modify some of the systemd services to change **Celery** logging to file, if you need that::
  
  -f PATH_TO_LOGFILE
