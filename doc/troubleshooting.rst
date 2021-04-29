Troubleshooting
=======

This part will references some issues and how to solve them. 

ERROR with service yeti_feed
------------------------------------
Remove celery.pid in your work environment.

It might have another error, you can follow the below steps:

- systemctl stop yeti_feeds.service

- mongo

- use yeti

- db.schedule_entry.drop()

- systemctl restart yeti_web.service

- systemctl restart yeti_feeds.service

- Relaunch feeders in /Dataflow page.

Performance issues
------------------------------------

At somepoint your Yeti instance might become slow. To solve that issue log in to mongo and enter the following commands:
- db.link.createIndex({"src.$id": 1})
- db.link.createIndex({"dst.$id": 1})
