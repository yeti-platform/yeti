# Testing at "Interface Value"

Tests in this directory run against the web interface in clever ways in order to tickle specific 
functionality. (Like SQL injection but for Good!)

If `core.config.config.yeti_config.yeti` exists it should define `host` and `port`; if it doesn't
exist, `host='localhost'` and `port=5000` are assumed.

In general you can just run these with Python.

(With apologies to _Sherry Turkle_ for using the term "interface value".)
