import mock
from wsgiref.simple_server import demo_app
from wsgiref.util import setup_testing_defaults

import pytest

import ags
from ags.oidc import AuthorizationCodeFlow


@pytest.fixture
def config():
    return {
        'AGS_BROKER_URL': 'http://broker',
        'AGS_BROKER_AUTH_ENDPOINT': '/auth',
        'AGS_BROKER_TOKEN_ENDPOINT': '/token',
        'AGS_BROKER_JWKS_URI': '/keys',
        'AGS_CLIENT_ID': 'test-client',
        'AGS_CLIENT_SECRET': 'test-secret',
        'AGS_CLIENT_AUTHENTICATED_URLS': 'foo'
    }


@pytest.fixture
def flow(config):
    return AuthorizationCodeFlow(config)


@pytest.fixture
def wsgi_stack(config):
    inner = mock.MagicMock()
    inner.side_effect = demo_app

    middleware = ags.Client(inner)
    middleware.config = config

    outer = mock.MagicMock()

    def call_client(environ, start_response):
        return middleware(environ, start_response)

    outer.side_effect = call_client

    return outer, middleware, inner


@pytest.fixture
def wsgi_request(wsgi_stack):
    outer, middleware, inner = wsgi_stack

    def make_request(url, data=None, headers={}):
        path, _, query = url.partition('?')
        environ = {
            'PATH_INFO': path,
            'QUERY_STRING': query,
            'REQUEST_METHOD': 'GET' if data is None else 'POST'}
        setup_testing_defaults(environ)
        environ.update(headers)

        start_response = mock.MagicMock()
        response = outer(environ, start_response)
        calls = start_response.mock_calls
        status = calls[0][1][0]
        headers = calls[0][1][1]
        return status, headers, response

    return make_request
