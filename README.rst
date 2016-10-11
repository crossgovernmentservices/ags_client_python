Accessing GaaP Services Client
==============================

.... image:: https://travis-ci.org/ministryofjustice/postcodeinfo-client-python.svg?branch=master
  ..:alt: Test result
  ..:target: http://ci.dsd.io/job/BUILD-postcodeinfo-client-python/lastCompletedBuild/testReport/

.... image:: https://coveralls.io/repos/ministryofjustice/postcodeinfo-client-python/badge.svg?branch=HEAD&service=github
  ..:target: https://coveralls.io/github/ministryofjustice/postcodeinfo-client-python?branch=HEAD
  ..:alt: Coverage report

.... image:: https://codeclimate.com/github/ministryofjustice/postcodeinfo-client-python/badges/gpa.svg
   ..:target: https://codeclimate.com/github/ministryofjustice/postcodeinfo-client-python
   ..:alt: Code Climate

.... image:: https://requires.io/github/ministryofjustice/postcodeinfo-client-python/requirements.svg?branch=master
     ..:target: https://requires.io/github/ministryofjustice/postcodeinfo-client-python/requirements/?branch=master
     ..:alt: Requirements Status

Python package providing an API client for accessing GaaP services.


Installation
------------

.. code-block:: bash

    pip install ags_client


Usage
-----

Registration
~~~~~~~~~~~~

You will need a *client ID* and *client secret* from the GaaP Identity Broker.
You can get these by emailing with a brief summary of:

* who you are
* what project you're going to be using it on


Quick Start
~~~~~~~~~~~

In your code:

.. code-block:: python

    >>> from ags_client import BrokerClient



Configuration
-------------

Apart from the client ID and secret, there is only one other parameter the API
client needs - ``broker_url``.

Explicit ``broker_url``
~~~~~~~~~~~~~~~~~~~~~~~

You can set the broker_url explicitly by passing it to the ``Client``
constructor

.. code-block:: python

    # create a client
    client = ags_client.Client(broker_url="https://some.dom.ain")

or by setting it on an existing client, like this

.. code-block:: python

    client = ags_client.Client()
    client.broker_url = "https://some.dom.ain"

Implicit ``broker_url``
~~~~~~~~~~~~~~~~~~~~~~~

If you don't pass an ``broker_url`` to the constructor, it will attempt to infer
one from the environment. The client has a built-in mapping of environment names
to URLs.

.. code-block:: python

    >>> ags_client.Client.broker_urls
    {
        'development': 'http://localhost:5556',
        'test': 'http://localhost:5556',
        'staging': 'http://dex.identity-k8s.civilservice.digital',
        'production': 'http://dex.identity-k8s.civilservice.digital'
    }

It will use the following rules to infer the URL:

1. If you pass an ``env`` parameter to the constructor (eg:
   ``client = ags_client.Client(env="staging")``), it will
   use that as a reference into the ``broker_urls`` mapping.
2. If you have ``DJANGO_SETTINGS_MODULE`` set in your environment, it will try
   to find the following settings in that module::

    AGS_BROKER_URL
    AGS_CLIENT_ID
    AGS_CLIENT_SECRET
3. If you have the following environment variables set, it will use them::

    AGS_BROKER_URL
    AGS_CLIENT_ID
    AGS_CLIENT_SECRET
3. Otherwise it will default to ``development``


Support
-------

This source code is provided as-is, with no incident response or support levels.
Please log all questions, issues, and feature requests in the Github issue
tracker for this repo, and we'll take a look as soon as we can. If you're
reporting a bug, then it really helps if you can provide the smallest possible
bit of code that reproduces the issue. A failing test is even better!


Contributing
------------

* Check out the latest master to make sure the feature hasn't been implemented
  or the bug hasn't been fixed
* Check the issue tracker to make sure someone hasn't already requested
  and/or contributed the feature
* Fork the project
* Start a feature/bugfix branch
* Commit and push until you are happy with your contribution
* Make sure your changes are covered by unit tests, so that we don't break it
  unintentionally in the future.
* Please don't mess with setup.py, version or history.


Copyright
---------

Copyright |copy| 2015 HM Government (Government Digital Service). See
LICENSE for further details.

.. |copy| unicode:: 0xA9 .. copyright symbol
