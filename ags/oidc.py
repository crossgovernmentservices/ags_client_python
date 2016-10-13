# -*- coding: utf-8 -*-
"""
OIDC client
"""

from urllib.parse import urlencode, urljoin
from urllib.request import Request


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

        self.params = {
            'scope': kwargs.pop('scope', ''),
            'response_type': kwargs.pop('response_type'),
            'client_id': kwargs.pop('client_id'),
            'redirect_uri': kwargs.pop('redirect_uri')
        }

        if 'openid' not in self.params['scope']:
            self.params['scope'] = 'openid {}'.format(self.params['scope'])

        if 'display' in kwargs:
            if kwargs['display'] not in DISPLAY_VALUES:
                raise AuthenticationRequestError(
                    'Invalid display value: {display}'.format(**kwargs))

        if 'prompt' in kwargs:
            if kwargs['prompt'] not in PROMPT_VALUES:
                raise AuthenticationRequestError(
                    'Invalid prompt value: {prompt}'.format(**kwargs))

        self.params.update(kwargs)

        super(AuthenticationRequest, self).__init__('{}?{}'.format(
            url, urlencode(self.params)))


class AuthorizationCodeFlow(object):

    def __init__(self, config):
        self.broker_url = config.get('AGS_BROKER_URL')
        self._auth_endpoint = config.get('AGS_BROKER_AUTH_ENDPOINT')
        self.client_id = config.get('AGS_CLIENT_ID')
        self.redirect_uri = 'http://localhost/oidc_callback'

    @property
    def auth_endpoint(self):
        if not self._auth_endpoint:

            if self.broker_url:
                self.load_broker_config()

        if self._auth_endpoint:
            return urljoin(self.broker_url, self._auth_endpoint)

        raise BrokerConfigError('Authentication endpoint not set')

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
