# -*- coding: utf-8 -*-

from base64 import urlsafe_b64encode
import datetime
import logging
from urllib.parse import urlencode
from urllib.request import Request

import requests

from ags.oidc.exceptions import AuthenticationRequestError, BrokerConfigError

from ags.logger import logger


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
            # ,'kc_idp_hint': "gds-google" # for silent log in via keycloak using only GDS google
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

        auth = '{client_id}:{client_secret}'.format(**kwargs).encode('utf-8')
        auth = 'Basic {}'.format(urlsafe_b64encode(auth).decode('latin1'))

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': auth
        }

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': kwargs.pop('redirect_uri'),
            'client_id': kwargs.pop('client_id'),
            'client_secret': kwargs.pop('client_secret')
        }
        data = urlencode(data)

        super(TokenRequest, self).__init__(url, data, headers)


class AuthorizationCodeFlow(object):

    def __init__(self, config):
        self.broker_url = config.get('AGS_BROKER_URL')
        self._auth_endpoint = config.get('AGS_BROKER_AUTH_ENDPOINT')
        self._token_endpoint = config.get('AGS_BROKER_TOKEN_ENDPOINT')
        self._jwks_uri = config.get('AGS_BROKER_JWKS_URI')
        self.client_id = config.get('AGS_CLIENT_ID')
        self.client_secret = config.get('AGS_CLIENT_SECRET')
        self.redirect_uri = config.get('AGS_CLIENT_CALLBACK_URL')
        self.id_token_signed_response_alg = 'RS256'
        self.clock_skew = datetime.timedelta(seconds=60)
        self.id_token_max_age = None
        self._keys = {}

    def build_url(self, path):
        return '{base_url}{path}'.format(base_url=self.broker_url, path=path)

    @property
    def auth_endpoint(self):
        if not self._auth_endpoint:

            if self.broker_url:
                self.load_broker_config()

        if self._auth_endpoint:
            return self.build_url(self._auth_endpoint)

        raise BrokerConfigError('Authentication endpoint not set')

    @property
    def jwks_uri(self):
        if not self._jwks_uri:

            if self.broker_url:
                self.load_broker_config()

        if self._jwks_uri:
            return self.build_url(self._jwks_uri)

        raise BrokerConfigError('JWKs URI not set')

    @property
    def token_endpoint(self):
        if not self._token_endpoint:

            if self.broker_url:
                self.load_broker_config()

        if self._token_endpoint:
            return self.build_url(self._token_endpoint)

        raise BrokerConfigError('Token endpoint not set')

    def authentication_request(self, **kwargs):
        return AuthenticationRequest(
            url=self.auth_endpoint,
            response_type='code',
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            **kwargs)

    def token_request(self, authz_code, **kwargs):
        return TokenRequest(
            url=self.token_endpoint,
            code=authz_code,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            **kwargs)

    def request_token(self, authz_code):
        req = self.token_request(authz_code)
        logger.debug("token request")
        logger.debug("url: {0.full_url}".format(req))
        logger.debug("data: {0.data}".format(req))
        logger.debug("headers: {0.headers}".format(req))
        return requests.post(
            req.full_url,
            data=req.data,
            headers=req.headers).json()

    def get_key(self, kid):
        if kid not in self._keys:
            key_data = requests.get(self.jwks_uri).json()
            self._keys = {key['kid']: key for key in key_data['keys']}

        return self._keys[kid]
