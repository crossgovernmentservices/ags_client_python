# -*- coding: utf-8 -*-
"""
Test OIDC Authorization Code Flow
"""

from base64 import urlsafe_b64encode as b64encode
import calendar
import datetime
from http.cookies import SimpleCookie
import mock
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat)
from jose import jwt
from jose.utils import base64url_encode
import pytest

from ags.oidc import (
    AuthenticationRequestError,
    IdToken)


@pytest.yield_fixture
def post():
    with mock.patch('ags.oidc.authz_flow.requests.post') as mock_post:
        yield mock_post


@pytest.fixture
def callback(post, wsgi_request, id_token):
    post.return_value.json.return_value = {
        'access_token': 'test-access-token',
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': 'test-refresh-token',
        'id_token': 'test-id-token'
    }
    req_headers = {'HTTP_COOKIE': 'ags_feature_switch_active=1'}
    return wsgi_request('/oidc_cb?code=test-code', headers=req_headers)


@pytest.fixture
def test_key():
    return rsa.generate_private_key(65537, 1024, default_backend())


@pytest.fixture
def test_jwk(test_key):
    return {
        'kid': 'test-key',
        'kty': 'RSA',
        'alg': 'RS256',
        'use': 'sig',
        'e': 'AQAB',
        'n': base64url_encode(
            test_key.public_key().public_numbers().n.to_bytes(
                128, byteorder='little')
        ).decode('utf-8')
    }


@pytest.fixture
def id_token(config, test_key, flow):
    headers = {
        'kid': 'test-key'
    }

    def tstamp(dt):
        return calendar.timegm(dt.utctimetuple())

    iat = datetime.datetime.utcnow()
    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

    pem = test_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('utf-8')

    def make_id_token(claims={}):
        payload = {
            'iss': config['AGS_BROKER_URL'],
            'sub': 'test-id',
            'aud': config['AGS_CLIENT_ID'],
            'iat': iat,
            'exp': exp,
            'email': 'test-user@example.com'
        }
        payload.update(claims)

        token = jwt.encode(payload, pem, jwt.ALGORITHMS.RS256, headers=headers)
        return IdToken(token, flow)

    return make_id_token


@pytest.yield_fixture
def keys(test_jwk):
    # XXX - verifying test signatures fails, but it's not important
    with mock.patch('jose.jws._sig_matches_keys') as sig_match:
        sig_match.return_value = True

        with mock.patch('ags.oidc.authz_flow.requests.get') as mock_get:
            mock_get.return_value.json.return_value = {"keys": [test_jwk]}
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
        req_headers = {'HTTP_COOKIE': 'ags_feature_switch_active=1'}
        status, headers, response = wsgi_request('/foo', headers=req_headers)
        state = '{"next_url": "http://127.0.0.1/foo"}'.encode('utf-8')
        auth_url = flow.authentication_request(state=b64encode(state)).full_url
        assert status == '302 Found'
        assert ('Location', auth_url) in headers

    def test_client_receives_authz_code(self, callback, flow):
        status, headers, response = callback
        state = '{"next_url": "http://127.0.0.1/oidc_cb?code=test-code"}'
        state = b64encode(state.encode('utf-8'))
        auth_url = flow.authentication_request(state=state).full_url
        assert ('Location', auth_url) not in headers

    @pytest.mark.xfail
    def test_client_handles_authn_error_response(self):
        assert False

    def test_client_requests_token_with_authz_code(self, post, callback, flow):
        req = flow.token_request('test-code')
        post.return_value.json.return_value = {}
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

    def test_client_validates_id_token(self, keys, id_token):
            id_token().is_valid()

    def test_client_passes_tokens_in_environ(
            self, keys, wsgi_stack, post, wsgi_request, id_token):

        outer, middleware, inner = wsgi_stack

        post.return_value.json.return_value = {
            'access_token': 'test-access-token',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': 'test-refresh-token',
            'id_token': id_token().token
        }

        cookie = SimpleCookie()
        cookie['ags_feature_switch_active'] = '1'

        req_headers = {'HTTP_COOKIE': 'ags_feature_switch_active=1'}
        status, headers, response = wsgi_request(
            '/oidc_cb?code=test-code', headers=req_headers)

        redirect_urls = [val for key, val in headers if key == 'Location']
        assert redirect_urls[0] == '/'

        for key, val in headers:
            if key == 'Set-cookie':
                cookie.load(val)

        req_headers['HTTP_COOKIE'] = ';'.join(
            m.OutputString() for m in cookie.values())

        status, headers, response = wsgi_request(
            redirect_urls[0],
            headers=req_headers)

        environ = inner.mock_calls[0][1][0]

        assert 'auth_data' in environ
        assert 'id_token' in environ['auth_data']
        assert isinstance(environ['auth_data']['id_token'], dict)
