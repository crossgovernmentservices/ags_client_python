# -*- coding: utf-8 -*-
"""
OIDC client Flask extension
"""

from urllib.parse import urlencode

from flask import url_for, current_app, request
from jose import jwt
import requests


class KeyNotFound(Exception):
    pass


def verify_id_token(token, config):
    header = jwt.get_unverified_header(token)
    keys = {key['kid']: key for key in config.get('keys', [])}
    key = keys.get(header['kid'])

    if not key:
        raise KeyNotFound(header["kid"])

    return jwt.decode(token, key, audience=config['client_id'])


class OIDC(object):
    """
    Flask extension which provides a simple API for OIDC authentication
    """

    def __init__(self, app=None):
        self._callback_fn = None
        self._config = {}
        if app:
            self.init_app(app)

    def init_app(self, app):
        self._app = app
        self._config = dict(app.config['OIDC_PROVIDERS'])

    def callback(self, fn):
        """
        Decorate a Flask view function to set as the OIDC callback handler
        """

        self._callback_fn = fn
        return fn

    def providers(self):
        return list(self._config.keys())

    def get_current_provider(self):
        return request.cookies.get('idp', self.providers()[0])

    def set_current_provider(self, idp):
        def set_idp_cookie(response):
            response.set_cookie('idp', idp)
            return response
        return set_idp_cookie

    @property
    def callback_url(self):
        """
        The OIDC callback/redirect URI
        """

        flipped_view_fns = {v: k for k, v in self._app.view_functions.items()}
        view_name = flipped_view_fns[self._callback_fn]
        return url_for(view_name, _external=True)

    def openid_config(self, provider_name):
        """
        Retrieve OpenID configuration for the specified IdP
        """

        config = self._config.get(provider_name, {})

        if config and 'authorization_endpoint' not in config:

            self._config[provider_name].update(requests.get(
                '{}/.well-known/openid-configuration'.format(
                    config['discovery_url'])).json())

            config = self.refresh_keys(provider_name)

        return config

    def refresh_keys(self, provider_name):
        """
        Load the JWKS keys from the provider
        """

        jwks_uri = self._config[provider_name].get('jwks_uri')

        if jwks_uri:
            self._config[provider_name].update(requests.get(jwks_uri).json())

        return self._config[provider_name]

    def login(self, force_reauthentication=False, **kwargs):
        """
        Generate a login URL for a provider
        """

        config = self.openid_config(self.get_current_provider())

        if force_reauthentication:
            kwargs["prompt"] = "login"
            kwargs["max_age"] = current_app.config.get("ACCEPT_SUIT_MAX_AGE")

        auth_request = AuthenticationRequest(
            scope='openid email profile',
            response_type='code',
            client_id=config['client_id'],
            redirect_uri=config.get('redirect_uri') or self.callback_url,
            **kwargs)

        return auth_request.url(config['authorization_endpoint'])

    def authenticate(self):
        """
        Authenticate a user and retrieve their userinfo
        """

        config = self.openid_config(self.get_current_provider())
        auth_code = request.args['code']

        token_response = self.token_request(config, auth_code)

        access_token = token_response['access_token']

        try:
            claims = verify_id_token(token_response['id_token'], config)

        except KeyNotFound:
            # refresh keys, in case they have been rotated
            config = self.refresh_keys(provider_name)
            claims = verify_id_token(token_response['id_token'], config)

        claims.update(self.userinfo(config, access_token))

        return claims

    def token_request(self, config, auth_code):
        """
        Exchange provider auth code for an ID Token and an Access Token
        """

        request = TokenRequest(
            grant_type='authorization_code',
            code=auth_code,
            redirect_uri=config.get('redirect_uri') or self.callback_url,
            client_id=config['client_id'],
            secret=config['client_secret'])

        response = request.send(config['token_endpoint'])

        if 'error' in response:
            raise Exception('{error}, {description}'.format(
                error=response['error'],
                description=response.get('error_description')))

        return response

    def userinfo(self, config, access_token):
        """
        Get userinfo Claims from the provider using an Access Token
        """

        if 'userinfo_endpoint' not in config:
            return {}

        request = UserInfoRequest(access_token)

        return request.send(config['userinfo_endpoint'])


class AuthenticationRequest(object):

    def __init__(self, scope, response_type, client_id, redirect_uri, **kw):
        if 'openid' not in scope:
            scope = 'openid {}'.format(scope)

        self._params = {
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'client_id': client_id,
            'scope': scope
        }

        self._params.update(kw)

    def url(self, auth_endpoint):
        params = urlencode(self._params)
        return '{}?{}'.format(auth_endpoint, params)


class TokenRequest(object):

    def __init__(self, grant_type, code, redirect_uri, client_id, secret):
        self.client_id = client_id
        self.client_secret = secret
        self._params = {
            'redirect_uri': redirect_uri,
            'code': code,
            'client_id': client_id,
            'client_secret': secret,
            'grant_type': grant_type}

    def send(self, token_endpoint):
        response = requests.post(
            token_endpoint,
            data=urlencode(self._params),
            auth=(self.client_id, self.client_secret),
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        return response.json()


class UserInfoRequest(object):

    def __init__(self, access_token):
        self.access_token = access_token

    def send(self, userinfo_endpoint):
        response = requests.get(
            userinfo_endpoint,
            headers={'Authorization': 'Bearer {token}'.format(
                token=self.access_token)})
        return response.json()
