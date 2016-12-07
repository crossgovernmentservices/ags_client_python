# -*- coding: utf-8 -*-
"""
Test OIDC Authorization Code Flow
"""

import json
import mock
from urllib.parse import parse_qs, unquote, urlparse

import pytest

import ags
from ags.oidc_client import TokenError


openid_configuration = {
    "authorization_endpoint": "https://broker/basepath/oidc/auth",
    "claims_parameter_supported": True,
    "end_session_endpoint": "https://broker/basepath/oidc/logout",
    "grant_types_supported": [
        "authorization_code",
        "implicit"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "issuer": "https://broker/basepath",
    "jwks_uri": "https://broker/basepath/oidc/keys",
    "registration_endpoint": "https://broker/basepath/oidc/registration",
    "request_parameter_supported": False,
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": True,
    "response_modes_supported": [
        "query",
        "fragment"
    ],
    "response_types_supported": [
        "code",
        "code id_token",
        "code token",
        "code id_token token"
    ],
    "scopes_supported": [
        "openid",
        "profile"
    ],
    "subject_types_supported": [
        "pairwise"
    ],
    "token_endpoint": "https://broker/basepath/oidc/token",
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic"
    ],
    "userinfo_endpoint": "https://broker/basepath/oidc/userinfo",
    "version": "3.0"
}


@pytest.fixture
def wsgi_app():
    app = mock.MagicMock()

    def handle(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['hello']

    app.side_effect = handle

    return app


@pytest.yield_fixture
def openid_conf():

    with mock.patch.object(ags.oidc_client.Client, 'http_request') as method:

        def http_request(url, method='GET', **kwargs):
            response = mock.MagicMock()
            response.status_code = 200

            if url.endswith('/.well-known/openid-configuration'):
                response.text = json.dumps(openid_configuration)

            return response

        method.side_effect = http_request

        yield


@pytest.yield_fixture
def token_request():

    with mock.patch.object(
            ags.oidc_client.Client, 'do_access_token_request') as method:

        method.return_value = {
            'id_token': {
                'nonce': ''
            },
            'access_token': ''
        }

        yield method


@pytest.yield_fixture
def userinfo(middleware):

    with mock.patch.object(middleware, 'get_tokens') as get_tokens:
        id_token = mock.MagicMock()
        id_token.__getitem__.return_value = 'test-sub'
        id_token.to_dict.return_value = {'sub': 'test-sub'}
        id_token.to_jwt.return_value = 'test-id-token-jwt'
        get_tokens.return_value = (id_token, 'test-access-token')

        with mock.patch.object(
                ags.oidc_client.Client, 'do_user_info_request') as method:
            userinfo = mock.MagicMock()
            userinfo.__getitem__.return_value = 'test-sub'
            userinfo.to_dict.return_value = {'sub': 'test-sub'}
            method.return_value = userinfo
            yield method


@pytest.yield_fixture
def middleware(openid_conf, wsgi_app):

    yield ags.oidc_client.OIDCAuthMiddleware(wsgi_app, {
        'DEBUG': False,
        'ISSUER': 'https://broker/basepath',
        'ID': 'test-client',
        'SECRET': 'test-secret',
        'AUTHENTICATED_PATHS': 'foo'
    })


@pytest.fixture
def request(middleware, wsgi_request):

    def make_request(url, data=None, headers={}):
        return wsgi_request(
            middleware, url, data=data, headers=headers)

    return make_request


@pytest.fixture
def handle_callback(request):

    def make_callback(url):
        status, headers, response = request(url)
        hdrs = dict(headers)
        parts = urlparse(hdrs['Location'])
        qs = parse_qs(parts.query)
        state = qs['state'][0]
        callback_url = unquote(qs['redirect_uri'][0])
        parts = urlparse(callback_url)
        callback_uri = '{}?code=test-code&state={}'.format(parts.path, state)
        return request(callback_uri)

    return make_callback


class TestOIDCAuthMiddleware(object):

    def test_request_auth_for_protected_paths(self, request):
        status, headers, response = request('/foo')
        headers = dict(headers)
        assert status == '302 Found'
        assert headers['Location'].startswith(
            'https://broker/basepath/oidc/auth')
        assert 'scope=openid' in headers['Location']
        assert 'response_type=code' in headers['Location']
        assert 'client_id=test-client' in headers['Location']
        assert 'nonce=' in headers['Location']
        assert 'state=' in headers['Location']
        assert 'redirect_uri=' in headers['Location']

    def test_exchange_code_for_token_on_callback(
            self, token_request, handle_callback):

        try:
            handle_callback('/foo')

        except TokenError:
            pass

        assert token_request.called

    def test_request_userinfo(self, userinfo, handle_callback):
        handle_callback('/foo')
        assert userinfo.called

    def test_client_passes_tokens_in_environ(
            self, cookie_jar, request, wsgi_app, userinfo, handle_callback):

        status, headers, content = handle_callback('/foo')
        assert status == '302 Found'

        hdrs = dict(headers)
        status, headers, content = request(hdrs['Location'])
        assert wsgi_app.called

        environ, start_response = wsgi_app.mock_calls[0][1]
        assert environ['auth_data']['id_token'] == {'sub': 'test-sub'}
        assert environ['auth_data']['access_token'] == 'test-access-token'

    def test_logout_redirects_to_idp_logout(
            self, cookie_jar, wsgi_app, request, userinfo, handle_callback):

        status, headers, content = handle_callback('/foo')
        status, headers, content = request(dict(headers)['Location'])

        status, headers, content = request('/sign-out')
        assert status == '302 Found'
        hdrs = dict(headers)
        assert openid_configuration['end_session_endpoint'] in hdrs['Location']
        assert 'id_token_hint=test-id-token-jwt' in hdrs['Location']

        parts = urlparse(hdrs['Location'])
        qs = parse_qs(parts.query)
        state = qs['state'][0]
        callback_url = unquote(qs['post_logout_redirect_uri'][0])
        callback_uri = '{}?state={}'.format(callback_url, state)

        status, headers, content = request(callback_uri)
        assert wsgi_app.called

        environ, start_response = wsgi_app.mock_calls[1][1]
        assert environ.get('auth_data', {}).get('id_token') is None
