The API
=======

This part details the various API endpoints that can be used within YETI.


Observables, Indicators and Entities
------------------------------------

Observables
^^^^^^^^^^^
.. autoflask:: core.web:webapp
  :endpoints: api.Observable:bulk, api.Observable:delete, api.Observable:get, api.Observable:index, api.Observable:new, api.Observable:post

.. autoflask:: core.web:webapp
  :endpoints: api.Tag:delete, api.Tag:get, api.Tag:index, api.Tag:merge, api.Tag:new, api.Tag:post

Indicators
^^^^^^^^^^
.. autoflask:: core.web:webapp
  :endpoints: api.Indicator:delete, api.Indicator:get, api.Indicator:index, api.Indicator:new, api.Indicator:post

Entities
^^^^^^^^
.. autoflask:: core.web:webapp
  :endpoints: api.Entity:index, api.Entity:get, api.Entity:delete, api.Entity:new, api.Entity:post

Searching
^^^^^^^^^
.. autoflask:: core.web:webapp
  :endpoints: api.ObservableSearch:post, api.ObservableSearch:search

.. autoflask:: core.web:webapp
  :endpoints: api.IndicatorSearch:post, api.IndicatorSearch:search

.. autoflask:: core.web:webapp
  :endpoints: api.EntitySearch:post, api.EntitySearch:search


Feeds and Exports
-----------------

.. autoflask:: core.web:webapp
  :endpoints: api.Export:content, api.Export:delete, api.Export:get, api.Export:index, api.Export:new, api.Export:post, api.Export:refresh, api.Export:toggle

.. autoflask:: core.web:webapp
  :endpoints: api.ExportTemplate:delete, api.ExportTemplate:get, api.ExportTemplate:index, api.ExportTemplate:new, api.ExportTemplate:post

.. autoflask:: core.web:webapp
  :endpoints: api.Feed:delete, api.Feed:get, api.Feed:index, api.Feed:new, api.Feed:post, api.Feed:refresh, api.Feed:toggle


Analysis
--------

.. autoflask:: core.web:webapp
   :endpoints: api.Analysis:match, api.Analysis:index, api.Analysis:get, api.Analysis:delete, api.Analysis:new, api.Analysis:post

.. autoflask:: core.web:webapp
  :endpoints: api.OneShotAnalytics:delete, api.OneShotAnalytics:get, api.OneShotAnalytics:index, api.OneShotAnalytics:new, api.OneShotAnalytics:post, api.OneShotAnalytics:run, api.OneShotAnalytics:status, api.OneShotAnalytics:toggle

.. autoflask:: core.web:webapp
  :endpoints: api.ScheduledAnalytics:delete, api.ScheduledAnalytics:get, api.ScheduledAnalytics:index, api.ScheduledAnalytics:new, api.ScheduledAnalytics:post, api.ScheduledAnalytics:refresh, api.ScheduledAnalytics:toggle


Investigation
-------------

.. autoflask:: core.web:webapp
  :endpoints: api.Investigation:add, api.Investigation:delete, api.Investigation:get, api.Investigation:index, api.Investigation:new, api.Investigation:post, api.Investigation:rename

.. autoflask:: core.web:webapp
  :endpoints: api.Neighbors:delete, api.Neighbors:get, api.Neighbors:index, api.Neighbors:new, api.Neighbors:post, api.Neighbors:tuples
