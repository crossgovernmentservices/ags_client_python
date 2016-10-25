# -*- coding: utf-8 -*-
"""
Test OIDC Authorization Code Flow
"""

import mock
from textwrap import dedent
from urllib.parse import parse_qs, urlparse
from wsgiref.simple_server import demo_app
from wsgiref.util import setup_testing_defaults

import pytest

import ags
from ags.oidc import (
    AuthenticationRequestError,
    AuthorizationCodeFlow,
    IdToken)


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

    def make_request(url, data=None, headers=[]):
        path, _, query = url.partition('?')
        environ = {
            'PATH_INFO': path,
            'QUERY_STRING': query,
            'REQUEST_METHOD': 'GET' if data is None else 'POST'}
        setup_testing_defaults(environ)

        start_response = mock.MagicMock()
        response = outer(environ, start_response)
        calls = start_response.mock_calls
        status = calls[0][1][0]
        headers = calls[0][1][1]
        return status, headers, response

    return make_request


@pytest.yield_fixture
def post():
    with mock.patch('ags.oidc.authz_flow.requests.post') as mock_post:
        yield mock_post


@pytest.fixture
def callback(post, wsgi_request):
    return wsgi_request('/oidc_cb?code=test-code')


@pytest.fixture
def test_key():
    return {
        "kid": "test-key",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "e": "AQAB",
        "n": dedent("""
            xQvzdm6pSJis1-4k8_Wi_B4FxWhWJmKExOd110knU_aQ5i7uBteGarQhdA4HIiBXOz
            Yxk1PQnSilZ-zF4SDmSfnyvv_IU8bcznp129_ASGqcwCe32KU1Mm4BS5zp3ywdYGxx
            oXw1kRp8bKUJEunVjzOI0H7n4_miNfYfHVYmlZpsWd2IptqRpEGftCNvF7tFkC1fuq
            xWzO5-iM-6ToAGo9WZQeRiXqffKF3D73Y1pMdE04Ok_75qqQuy5i8G6VAMfljckQRY
            OmkANZaLNX7wfRhUdPq6qauoU5sx5EWc3gpDcsmZvoNnRRYnWB1XGHCrg3LyiLSuxh
            t9sk3oEhyIFw==
        """).replace("\n", '')
    }


@pytest.fixture
def id_token():
    token = dedent("""
        eyJhbGciOiJSUzI1NiIsImtpZCI6IjRmYjE1NjVlYWRlNTFiOWMzYTUyYmU0NDI0YjNjY
        TkxYzM4ZjUzNjUiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiI4cHJZb1p5bTB6a3Q2WnpUSWJ
        YYUZCUXZ0cldpMkE4eG1kQzlXRXozaTE0PUBsb2NhbGhvc3QiLCJlbWFpbCI6Imtlbi50
        c2FuZ0BkaWdpdGFsLmNhYmluZXQtb2ZmaWNlLmdvdi51ayIsImVtYWlsX3ZlcmlmaWVkI
        jp0cnVlLCJleHAiOjE0NzM4OTYzNjYsImlhdCI6MTQ3Mzg1MzE2NiwiaXNzIjoiaHR0cD
        ovL2RleC5leGFtcGxlLmNvbTo1NTU2IiwibmFtZSI6IiIsInN1YiI6IjZjN2E5ZjQ1LTd
        mNTctNGQ5MS1iZTBlLTI4NjY3M2EyOGM2ZiJ9.tAVC2OD70vuTiARWoSagm37xQcWZ3o8
        W9jLvW8mHG39MgOp6GHGhyJuTgvkciDqi10SqHMcaGH9jSZepVUkQBNYPKejp9VZ3iiXy
        q731ckzoY93q5TvSOqjkoG7_HxXCkD5RX2F6XdTq_Se231TSEgWPxYl3ycLzKtNMeD5o3
        Aq8z_ypzgl7kQmEEdZWPSAcQr7-6IIHJ38UgDZfPhTYtUB4f_abgXXcuQV10uWkXBMdOz
        fM2s9ByexSAvL2-HVs_jtdC3C-Rwu_05yKfduVO5yiNBxoyrkv2yZgEhfKNh1WLYj2cb0
        8cs4iw4u8QSEOSEzL5Gy1wXPdL78aoaqUYg
    """).replace("\n", '')
    return IdToken(token, flow)


@pytest.yield_fixture
def keys(test_key):
    with mock.patch('ags.oidc.authz_flow.requests.get') as mock_get:
        mock_get.return_value.json.return_value = {"keys": [test_key]}
        yield mock_get


class TestAuthzCodeFlow(object):

    def test_client_prepares_authn_request(self, flow):
        request = flow.authentication_request()
        parts = urlparse(request.full_url)
        params = parse_qs(parts.query)
        required_params = set([
            'scope',
            'response_type',
            'client_id',
            'redirect_uri'])

        assert required_params.issubset(params.keys())
        assert 'openid' in params['scope'][0]
        assert params['response_type'][0] == 'code'
        assert params['client_id'][0] == 'test-client'

    @pytest.mark.parametrize('params,expected', [
        ({'scope': 'openid'}, 'scope=openid'),
        ({'scope': ''}, 'scope=openid'),
        ({'scope': 'email profile'}, 'scope=openid+email+profile'),
        ({'state': 'test-state'}, 'state=test-state'),
        ({'prompt': 'none'}, 'prompt=none'),
        ({'prompt': 'login'}, 'prompt=login'),
        ({'prompt': 'consent'}, 'prompt=consent'),
        ({'prompt': 'select_account'}, 'prompt=select_account'),
        ({'prompt': 'login consent'}, 'prompt=login+consent'),
        (
            {'prompt': 'consent select_account'},
            'prompt=consent+select_account'),
        (
            {'prompt': 'login select_account'},
            'prompt=login+select_account'),
        (
            {'prompt': 'login consent select_account'},
            'prompt=login+consent+select_account'),
        ({'max_age': 300}, 'max_age=300'),
        ({'display': 'page'}, 'display=page'),
        ({'display': 'popup'}, 'display=popup'),
        ({'display': 'touch'}, 'display=touch'),
        ({'display': 'wap'}, 'display=wap'),
    ])
    def test_authn_request_accepts_valid_params(self, flow, params, expected):
        request = flow.authentication_request(**params)
        assert expected in request.full_url

    @pytest.mark.parametrize('params', [
        {'prompt': 'foo'},
        {'prompt': ''},
        {'prompt': 0},
        {'prompt': 'none login'},
        {'prompt': 'none consent'},
        {'prompt': 'none select_account'},
        {'prompt': 'none consent login'},
        {'prompt': 'none consent select_account'},
        {'prompt': 'none login select_account'},
        {'prompt': 'none consent login select_account'},
        {'display': 'foo'},
        {'display': ''},
        {'display': 0},
    ])
    def test_authn_request_reject_invalid_params(self, flow, params):
        with pytest.raises(AuthenticationRequestError):
            flow.authentication_request(**params)

    def test_client_sends_request_to_authz_server(self, wsgi_request, flow):
        status, headers, response = wsgi_request('/foo')
        auth_url = flow.authentication_request().full_url
        assert status == '302 Found'
        assert ('Location', auth_url) in headers

    def test_client_receives_authz_code(self, callback, flow):
        status, headers, response = callback
        auth_url = flow.authentication_request().full_url
        assert ('Location', auth_url) not in headers

    @pytest.mark.xfail
    def test_client_handles_authn_error_response(self):
        assert False

    def test_client_requests_token_with_authz_code(self, post, callback, flow):
        req = flow.token_request('test-code')
        post.assert_called_with(
            req.full_url,
            data=req.data,
            headers=req.headers)

    def test_client_receives_id_and_access_tokens(self, post, flow):
        post.return_value.json.return_value = {
            'access_token': 'test-access-token',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': 'test-refresh-token',
            'id_token': 'test-id-token'
        }
        token_response = flow.request_token('test-code')
        assert token_response['id_token'] == 'test-id-token'
        assert token_response['access_token'] == 'test-access-token'

    @pytest.mark.xfail
    def test_client_validates_id_token(self, id_token):
        id_token.is_valid()
