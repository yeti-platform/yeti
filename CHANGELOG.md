# Version 1.2

## Breaking changes

The database structure has changed a bit. If you're migrating from 1.1, you have two choices.

* Run the following script to update the database structure (you have tou be `source`'d and in Malcom's root directory)

        from Malcom.analytics.analytics import Analytics
        import datetime
        a = Analytics()

        for e in a.data.elements.find():
          e['refresh_period'] = e.default_refresh_period
          e['next_analysis'] = datetime.datetime.utcnow()
          a.save_element(e)

This will run analytics on all elements on the next analytics round (which might take a while)

* Clear your DB and start over.

