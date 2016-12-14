import os
import re
from urllib.parse import parse_qs, urljoin
from wsgiref.util import request_uri

from beaker.middleware import SessionMiddleware
from oic import rndstr
from oic.oauth2.exception import MissingEndpoint
from oic.oic import Client
from oic.oic.message import (
    AuthorizationResponse,
    EndSessionRequest,
    RegistrationRequest)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from ags.logger import get_logger
from ags.route import RouteNotMatched, Router


def redirect(url, start_response):
    start_response('302 Found', [('Location', url)])
    return [b'']


class OIDCClientError(Exception):
    pass


class AuthError(OIDCClientError):
    pass


class SignOutError(OIDCClientError):
    pass


class TokenError(OIDCClientError):
    pass


class UserinfoError(OIDCClientError):
    pass


class OIDCAuthMiddleware(object):

    def __init__(self, app, config):
        self.app = app
        self.config = config

        self.logger = get_logger(__name__)

        self.router = Router()

        self.setup_routes()

        self.wsgi_app = SessionMiddleware(self.router, {
            'session.auto': True,
            'session.cookie_expires': True,
            'session.data_dir': '/tmp',
            'session.lock_dir': '/tmp',
            'session.key': config.get('SESSION_COOKIE', 'ags_client_session'),
            'session.secret': config.get('SESSION_SECRET', 'secret'),
            'session.type': 'file'})

        client = Client(
            client_authn_method=CLIENT_AUTHN_METHOD,
            verify_ssl=(config.get('VERIFY_SSL', True) != 'False'))
        client.provider_config(config['ISSUER'])

        client.store_registration_info(RegistrationRequest(
            redirect_uris=[],
            client_id=config['ID'],
            client_secret=config['SECRET']
        ))

        self.client = client

    def __call__(self, environ, start_response):
        try:
            return self.wsgi_app(environ, start_response)

        except RouteNotMatched:
            pass

        return self.app(self.auth_data(environ), start_response)

    def authenticate(self, environ, start_response):
        session = environ['beaker.session']

        if self.reauthentication_necessary(session):

            self.logger.info('Redirecting to {idp} for authentication'.format(
                idp=self.config['ISSUER']))

            session.update({
                'destination': request_uri(environ, include_query=True),
                'state': rndstr(),
                'nonce': rndstr()
            })

            return redirect(
                self.auth_request(session, environ), start_response)

        return self.app(self.auth_data(environ), start_response)

    def auth_request(self, session, environ):
        auth_req = self.client.construct_AuthorizationRequest(
            request_args={
                'client_id': self.client.client_id,
                'response_type': 'code',
                'scope': ['openid', 'profile'],
                'redirect_uri': self.callback_url(environ),
                'state': session['state'],
                'nonce': session['nonce'],
                'claims': {
                    'userinfo': {
                        'email': {'essential': True},
                        'name': {'essential': True}
                    }
                }
            }
        )

        return auth_req.request(self.client.authorization_endpoint)

    def callback_url(self, environ):
        if isinstance(environ['QUERY_STRING'], bytes):
            environ['QUERY_STRING'] = environ['QUERY_STRING'].decode('utf-8')
        return urljoin(
            request_uri(environ),
            '/{}'.format(self.config.get('CALLBACK_PATH', 'oidc_callback')))

    def reauthentication_necessary(self, session):
        return session.get('id_token') is None

    def callback(self, environ, start_response):
        self.logger.info('Handling authentication callback')

        session = environ['beaker.session']
        environ['QUERY_STRING'] = environ['QUERY_STRING'].encode('utf-8')

        try:
            code, state = self.parse_auth_response(environ)

        except Exception as error:
            self.logger.error(str(error))
            raise error

        self.logger.info('Exchanging authz code for access and id tokens')

        id_token, access_token = self.get_tokens(code, state, session, environ)

        self.logger.info('Requesting userinfo')

        userinfo = self.get_userinfo(id_token, state)

        session.update({
            'id_token': id_token.to_dict(),
            'id_token_jwt': id_token.to_jwt(),
            'access_token': access_token
        })

        if userinfo:
            session['userinfo'] = userinfo.to_dict()

        self.logger.info('Redirecting to {destination}'.format(
            destination=session.get('destination')))

        return redirect(session.pop('destination'), start_response)

    def auth_data(self, environ):
        session = environ['beaker.session']

        if 'id_token' in session:
            environ.update({
                'auth_data': {
                    'id_token': session.get('id_token'),
                    'id_token_jwt': session.get('id_token_jwt'),
                    'access_token': session.get('access_token'),
                    'userinfo': session.get('userinfo')
                }
            })

        elif 'auth_data' in environ:
            del environ['auth_data']

        return environ

    def parse_auth_response(self, environ):
        session = environ['beaker.session']
        auth_response = self.client.parse_response(
            AuthorizationResponse,
            info=environ['QUERY_STRING'].decode('utf-8'),
            sformat='urlencoded')

        state = auth_response.get('state')

        if state != session.get('state'):
            raise AuthError("Server 'state' parameter does not match")

        if 'state' in session:
            del session['state']

        return auth_response['code'], state

    def get_tokens(self, code, state, session, environ):
        args = {
            'code': code,
            'redirect_uri': self.callback_url(environ),
        }

        try:
            token_response = self.client.do_access_token_request(
                state=state,
                request_args=args,
                authn_method=self.client.registration_response.get(
                    'token_endpoint_auth_method', 'client_secret_basic'))

        except Exception as exc:
            raise OIDCClientError(exc)

        id_token = token_response['id_token']
        if id_token['nonce'] != session.pop('nonce'):
            raise TokenError("ID Token 'nonce' parameter does not match")

        return id_token, token_response['access_token']

    def get_userinfo(self, id_token, state):
        try:
            userinfo = self.client.do_user_info_request(
                method='POST', state=state)

        except MissingEndpoint:
            return None

        if userinfo['sub'] != id_token['sub']:
            raise UserinfoError(
                "The userinfo 'sub' does not match the id token 'sub'")

        return userinfo

    def sign_out(self, environ, start_response):
        session = environ['beaker.session']
        id_token_jwt = session.get('id_token_jwt')

        if id_token_jwt and not self.is_sign_out_callback(environ):
            self.logger.info('Clearing session')
            session.clear()

            url = self.provider_logout_url(id_token_jwt, environ)
            if url:
                self.logger.info('Logging out of IDP')
                return redirect(url, start_response)

        environ = self.auth_data(environ)
        return self.app(environ, start_response)

    def is_sign_out_callback(self, environ):
        session = environ['beaker.session']
        request_args = parse_qs(environ['QUERY_STRING'])
        state = request_args.get('state', [None])[0]
        is_redirect = state is not None

        if is_redirect and state != session.get('end_session_state'):
            raise SignOutError('Server state does not match')

        return is_redirect

    def provider_logout_url(self, id_token_jwt, environ):
        session = environ['beaker.session']
        endpoint = self.client.provider_info.get('end_session_endpoint')

        if not endpoint:
            return None

        session['end_session_state'] = rndstr()

        end_session_request = EndSessionRequest(
            id_token_hint=id_token_jwt,
            post_logout_redirect_uri=self.sign_out_url(environ),
            state=session['end_session_state'])

        return end_session_request.request(endpoint)

    def sign_out_url(self, environ):
        if isinstance(environ['QUERY_STRING'], bytes):
            environ['QUERY_STRING'] = environ['QUERY_STRING'].decode('utf-8')
        return urljoin(
            request_uri(environ),
            '/{}'.format(self.config.get('SIGN_OUT_PATH', 'sign-out')))

    def setup_routes(self):
        for path in self.config.get('AUTHENTICATED_PATHS', '').split(','):
            self.router.route(
                '^/{}/?$'.format(re.escape(path)))(self.authenticate)

        self.router.route(
            '^/{}/?$'.format(re.escape(
                self.config.get('CALLBACK_PATH', 'oidc_callback')))
            )(self.callback)

        self.router.route(
            '^/{}/?$'.format(re.escape(
                self.config.get('SIGN_OUT_PATH', 'sign-out')))
            )(self.sign_out)
