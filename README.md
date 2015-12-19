Install dependencies:

    $ sudo apt-get install build-essential git python-dev mongodb libxml2-dev libxslt-dev zlib1g-dev python-virtualenv

Activate virtualenv, then install requirements:

    $ pip install -r requirements.txt

Start the web UI (will spawn a listener on `http://localhost:5000`:

    $ ./yeti.py

To to start celery jobs (feeds and analysis):

    $ celery -A core.config.celeryctl worker --loglevel=INFO
    $ celery -A core.config.celeryctl beat -S core.scheduling.Scheduler --loglevel=INFO
