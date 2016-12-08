Accessing GaaP Services Client
==============================

.. image:: https://travis-ci.org/crossgovernmentservices/ags_client_python.svg?branch=master
  :alt: Test result

Python package providing a WSGI middleware for accessing GaaP services.


Installation
------------

.. code-block:: bash

    pip3 install ags_client


Usage
-----

Registration
~~~~~~~~~~~~

You will need a *client ID* and *client secret* from the GaaP Identity Broker.
You can't get these yet, but soon will by emailing us with a brief summary of:

* who you are
* what project you're going to be using it on


Quick Start
~~~~~~~~~~~

**Flask**

For example: given your Flask app is defined in ``webservice.py`` in a variable
named ``app``, create a file called ``wsgi.py``:

.. code-block:: python

    import ags

    from webservice import app


    app.wsgi_app = ags.Client(app.wsgi_app)

Then start your app with a WSGI server such as Gunicorn or uWSGI. Eg:

.. code-block:: shell

    gunicorn wsgi:app


Configuration
-------------

The middleware looks for certain environment variables for settings. The
following variables are **REQUIRED**:

``AGS_CLIENT_ISSUER``
    The URL of the OIDC identity broker

``AGS_CLIENT_ID``
    The client ID that you have been issued

``AGS_CLIENT_SECRET``
    The client secret that you have been issued

``AGS_CLIENT_AUTHENTICATED_PATHS``
    Comma separated list of paths in your web application that require
    authentication. May include regular expressions.

``AGS_CLIENT_SIGN_OUT_PATH``
    Path to sign out view in your application - default: ``sign-out``

The following variables are **OPTIONAL**:

``AGS_CLIENT_DEBUG``
    If set to ``True``, errors will be handled by the Werkzeug debugger. DO NOT
    USE IN PRODUCTION!

``AGS_CLIENT_LOG_PATH``
    Log to the specified file, in addition to console

``AGS_CLIENT_SESSION_COOKIE``
    The name of the cookie used to store the session ID - default:
    ``ags_client_session``

``AGS_CLIENT_SESSION_SECRET``
    The secret key use to encrypt the session cookie - default: generates a new
    secret on start-up

    .. note::
       Override this value when deploying across multiple hosts, otherwise
       sessions may become invalid across requests

The following variables can be used to override defaults, but usually should
not be used:

``AGS_CLIENT_CALLBACK_PATH``
    Overrides default OIDC callback path

``AGS_CLIENT_FEATURE_FLAG_COOKIE``
    The name of the cookie used to store the feature flag status - default:
    ``ags_client_active``

``AGS_CLIENT_FEATURE_FLAG_DEFAULT``
    The default state of the feature flag if the cookie is not set - default:
    ``True``

``AGS_CLIENT_VERIFY_SSL``
    If ``False``, verification of the broker's SSL certificate is skipped


Usage
-----

When activated, the middleware will intercept requests to the paths specified in
the ``AGS_CLIENT_AUTHENTICATED_PATHS`` environment variable and perform OpenID
Connect authentication before passing the user authentication details on to the
wrapped application.

It will also intercept requests to the ``AGS_CLIENT_SIGN_OUT_PATH`` and end the
session on the identity broker before passing through to the wrapped
application.

Activation
==========

The middleware is activated by default, unless the
``AGS_CLIENT_FEATURE_FLAG_DEFAULT`` environment variable is set to ``False``.

The middleware is activated or deactivated via a feature flag cookie, which can
be toggled by browsing to ``/toggle-feature/{FLAG}``, where ``{FLAG}`` is the
value of the ``AGS_CLIENT_FEATURE_FLAG_COOKIE`` environment variable or the
default value ``ags_client_active``.


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

Copyright |copy| 2016 HM Government (Government Digital Service). See
LICENSE for further details.

.. |copy| unicode:: 0xA9 .. copyright symbol
