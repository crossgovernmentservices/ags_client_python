# -*- coding: utf-8 -*-
"""
Test OIDC Authorization Code Flow
"""

import mock
from urllib.parse import parse_qs, urlparse
from wsgiref.simple_server import demo_app
from wsgiref.util import setup_testing_defaults

import pytest

import ags
from ags.oidc import AuthenticationRequestError, AuthorizationCodeFlow


@pytest.fixture
def config():
    return {
        'AGS_BROKER_URL': 'http://broker',
        'AGS_BROKER_AUTH_ENDPOINT': '/auth',
        'AGS_BROKER_TOKEN_ENDPOINT': '/token',
        'AGS_CLIENT_ID': 'test-client',
        'AGS_CLIENT_SECRET': 'test-secret'
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
    with mock.patch('ags.oidc.requests.post') as mock_post:
        yield mock_post


@pytest.fixture
def callback(post, wsgi_request):
    return wsgi_request('/oidc_cb?code=test-code')


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
        status, headers, response = wsgi_request('/')
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
    def test_client_validates_id_token(self):
        assert False
