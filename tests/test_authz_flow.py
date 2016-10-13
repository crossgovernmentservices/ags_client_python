# -*- coding: utf-8 -*-
"""
Test OIDC Authorization Code Flow
"""

from urllib.parse import parse_qs, urlparse

import pytest

from ags.oidc import AuthorizationCodeFlow


@pytest.fixture
def test_config():
    return {
        'AGS_BROKER_URL': 'http://broker',
        'AGS_BROKER_AUTH_ENDPOINT': '/auth',
        'AGS_CLIENT_ID': 'test-client',
        'AGS_CLIENT_SECRET': 'test-secret'
    }


@pytest.fixture
def flow(test_config):
    return AuthorizationCodeFlow(test_config)


class TestAuthzCodeFlow(object):

    @pytest.mark.parametrize('params,expected', [
        ({'scope': 'openid'}, 'scope=openid'),
        ({'scope': ''}, 'scope=openid'),
        ({'scope': 'email profile'}, 'scope=openid+email+profile'),
        ({'state': 'test-state'}, 'state=test-state'),
        ({'prompt': 'login'}, 'prompt=login'),
        ({'prompt': 'consentfoo'}, None),
        ({'max_age': 300}, 'max_age=300'),
        ({'display': 'page'}, 'display=page'),
        ({'display': 'foo'}, None),
    ])
    def test_client_prepares_authn_request(self, flow, params, expected):
        try:
            request = flow.authentication_request(**params)

        except:
            if expected is None:
                return True
            raise

        assert expected in request.full_url

        parts = urlparse(request.full_url)
        params = parse_qs(parts.query)
        assert 'openid' in params['scope'][0]
        assert params['response_type'][0] == 'code'
        assert params['client_id'][0] == 'test-client'
        assert 'redirect_uri' in params

    def test_client_sends_request_to_authz_server(self):
        pass

    def test_client_receives_authz_code(self):
        pass

    def test_client_requests_token_using_authz_code(self):
        pass

    def test_client_receives_id_and_access_tokens(self):
        pass

    def test_client_validates_id_token(self):
        pass
