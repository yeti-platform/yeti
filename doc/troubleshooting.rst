Troubleshooting
=======

This part will references some issues and how to solve them. 

ERROR with service yeti_feed
------------------------------------
Remove celery.pid in your work environment.

It might have another error, you can follow the below steps:

systemctl stop yeti_feed.service

mongo

use yeti

db.schedule_entry.drop()

systemctl restart yeti_web.service

systemctl restart yeti_feed.service

Relaunch feeders in /Dataflow page.
