# -*- coding: utf-8 -*-
"""
OIDC client
"""

from urllib.parse import urlencode, urljoin
from urllib.request import Request

import requests


class AuthenticationRequestError(Exception):
    pass


class BrokerConfigError(Exception):
    pass


class AuthenticationResult(object):

    def __init__(self):
        pass


DISPLAY_VALUES = ['page', 'popup', 'touch', 'wap']
PROMPT_VALUES = ['none', 'login', 'consent', 'select_account']


class AuthenticationRequest(Request):

    def __init__(self, url, **kwargs):

        scope = list(filter(None, kwargs.pop('scope', '').split(' ')))
        if 'openid' not in scope:
            scope = ['openid'] + scope

        self.params = {
            'scope': ' '.join(scope),
            'response_type': kwargs.pop('response_type'),
            'client_id': kwargs.pop('client_id'),
            'redirect_uri': kwargs.pop('redirect_uri')
        }

        if 'display' in kwargs:
            if not kwargs['display']:
                raise AuthenticationRequestError(
                    'Invalid display value: empty string')

            if not isinstance(kwargs['display'], str):
                raise AuthenticationRequestError(
                    'Invalid display value: must be string')

            if kwargs['display'] not in DISPLAY_VALUES:
                raise AuthenticationRequestError(
                    'Invalid display value: {display}'.format(**kwargs))

        if 'prompt' in kwargs:
            if not kwargs['prompt']:
                raise AuthenticationRequestError(
                    'Invalid prompt value: empty string')

            if not isinstance(kwargs['prompt'], str):
                raise AuthenticationRequestError(
                    'Invalid prompt value: must be space-delimited string')

            vals = list(filter(None, kwargs.get('prompt', '').split(' ')))

            if not set(vals).issubset(PROMPT_VALUES):
                raise AuthenticationRequestError(
                    'Invalid prompt value: {prompt}'.format(**kwargs))

            if 'none' in vals and len(vals) > 1:
                raise AuthenticationRequestError(
                    'Invalid prompt value: {prompt}'.format(**kwargs))

        self.params.update(kwargs)

        super(AuthenticationRequest, self).__init__('{}?{}'.format(
            url, urlencode(self.params)))


class TokenRequest(Request):

    def __init__(self, url, code, **kwargs):

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic {}'.format(kwargs.pop('client_secret'))
        }

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': kwargs.pop('redirect_uri'),
            'client_id': kwargs.pop('client_id')
        }
        data = urlencode(data)

        super(TokenRequest, self).__init__(url, data, headers)


class AuthorizationCodeFlow(object):

    def __init__(self, config):
        self.broker_url = config.get('AGS_BROKER_URL')
        self._auth_endpoint = config.get('AGS_BROKER_AUTH_ENDPOINT')
        self._token_endpoint = config.get('AGS_BROKER_TOKEN_ENDPOINT')
        self.client_id = config.get('AGS_CLIENT_ID')
        self.client_secret = config.get('AGS_CLIENT_SECRET')
        self.redirect_uri = 'http://localhost/oidc_callback'

    @property
    def auth_endpoint(self):
        if not self._auth_endpoint:

            if self.broker_url:
                self.load_broker_config()

        if self._auth_endpoint:
            return urljoin(self.broker_url, self._auth_endpoint)

        raise BrokerConfigError('Authentication endpoint not set')

    @property
    def token_endpoint(self):
        if not self._token_endpoint:

            if self.broker_url:
                self.load_broker_config()

        if self._token_endpoint:
            return urljoin(self.broker_url, self._token_endpoint)

        raise BrokerConfigError('Token endpoint not set')

    def authenticate_user(self):
        """
        """

        return AuthenticationResult()

    def authentication_request(self, **kwargs):
        """
        Construct authentication request URL
        """

        return AuthenticationRequest(
            url=self.auth_endpoint,
            response_type='code',
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            **kwargs)

    def token_request(self, authz_code, **kwargs):
        """
        Construct token request URL
        """

        return TokenRequest(
            url=self.token_endpoint,
            code=authz_code,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            **kwargs)

    def request_token(self, authz_code):
        req = self.token_request(authz_code)
        return requests.post(
            req.full_url,
            data=req.data,
            headers=req.headers).json()
