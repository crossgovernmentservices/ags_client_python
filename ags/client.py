# -*- coding: utf-8 -*-
"""
AGS Client class
"""

from base64 import (
    urlsafe_b64decode as b64decode,
    urlsafe_b64encode as b64encode)
from functools import wraps
import json
import logging
import os
import re
from urllib.parse import parse_qs
from wsgiref.util import request_uri

from beaker.middleware import SessionMiddleware
from cached_property import cached_property, threaded_cached_property

from ags import oidc


class HttpError(Exception):

    def __init__(self, status, message=None):
        self.status = status
        self.message = message

    def response(self, environ, start_response):
        start_response(self.status, [
            ('Content-Type', 'text/plain; charset=utf-8')])
        if self.message:
            return [self.message.encode('utf-8')]


def handle_errors(fn):

    @wraps(fn)
    def handler(self, environ, start_response):
        try:
            return fn(self, environ, start_response)

        except HttpError as error:
            return error.response(environ, start_response)

        except Exception as exc:
            error = HttpError('500 Internal Error', str(exc))
            return error.response(environ, start_response)

    return handler


class Client(object):

    def __init__(self, app):
        self.app = app
        self.beaker = SessionMiddleware(self.wsgi_app, {
            'session.data_dir': '/tmp',
            'session.lock_dir': '/tmp',
            'session.auto': True,
            'session.key': 'ags_session',
            'session.secret': 'secret',
            'session.type': 'file',
            'session.cookie_expires': True})
        self.config = {}
        for k in os.environ:
            if k.startswith('AGS_'):
                self.config[k] = os.environ[k]

    def __call__(self, environ, start_response):
        return self.beaker(environ, start_response)

    @handle_errors
    def wsgi_app(self, environ, start_response):

        self.load_auth_data(environ)

        if self.should_authenticate(environ):
            authentication_request = self.authentication_request(environ)
            self.logger.debug('redirecting to broker {}'.format(
                authentication_request))
            return self.redirect(start_response, authentication_request)

        if self.is_callback(environ):
            self.logger.debug('{} matches callback url pattern {}'.format(
                self.request_path(environ), self.callback_url_pattern))
            return self.callback(environ, start_response)

        return self.app(environ, start_response)

    @handle_errors
    def callback(self, environ, start_response):
        code = self.authorization_code(environ)
        state = self.callback_state(environ)

        self.logger.debug('received authz code {}'.format(code))
        self.logger.debug('received state {}'.format(state))

        if code is None:
            raise HttpError('400 Bad Request', 'Missing code')

        token_response = self.token_request(code)
        self.logger.debug('received token response {}'.format(token_response))

        id_token = oidc.token.IdToken(token_response['id_token'], self.flow)
        id_token.is_valid()

        session = environ['beaker.session']
        session['auth_data'] = {
            'id_token': id_token.token,
            'access_token': token_response['access_token']}
        self.logger.debug('saved session {}'.format(session))

        next_url = '/'

        if state and 'next_url' in state:
            next_url = state['next_url']

        return self.redirect(start_response, next_url)

    def authentication_request(self, environ):
        state = self.state(environ)
        return self.flow.authentication_request(state=state).full_url

    def authorization_code(self, environ):
        query_string = parse_qs(environ['QUERY_STRING'])
        return query_string.get('code', [None])[0]

    def callback_state(self, environ):
        query_string = parse_qs(environ['QUERY_STRING'])
        state = query_string.get('state', [None])[0]

        if not state:
            return None

        return json.loads(b64decode(state).decode('utf-8'))

    @property
    def callback_url_pattern(self):
        path = self.config.get('AGS_CLIENT_CALLBACK_PATH', 'oidc_cb')
        return re.compile(r'^{}/?$'.format(path))

    @property
    def flow(self):
        return oidc.AuthorizationCodeFlow(self.config)

    def is_callback(self, environ):
        return self.callback_url_pattern.match(self.request_path(environ))

    def load_auth_data(self, environ):
        session = environ.get('beaker.session')
        if session and session.get('auth_data', False):
            self.logger.debug('loading auth data from session: {}'.format(
                session['auth_data']))
            environ['auth_data'] = session['auth_data']

    @cached_property
    def logger(self):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def redirect(self, start_response, url):
        start_response('302 Found', [('Location', url)])
        return [b'']

    def request_path(self, environ):
        return environ.get('PATH_INFO', '').lstrip('/')

    def requires_authentication(self, environ):
        path = self.request_path(environ)

        for url_pattern in self.authenticated_urls:

            if url_pattern.match(path):
                self.logger.debug('{} requires authentication'.format(path))
                return True

        return False

    def should_authenticate(self, environ):

        if self.requires_authentication(environ):

            if self.user_authenticated(environ):
                self.logger.debug('user already authenticated')
                return False

            return True

        return False

    def state(self, environ):
        return b64encode(json.dumps({
            'next_url': request_uri(environ)
        }).encode('utf-8'))

    def token_request(self, code):
        return self.flow.request_token(code)

    def user_authenticated(self, environ):
        session = environ.get('beaker.session', {})
        return session and session.get('auth_data', False)

    @threaded_cached_property
    def authenticated_urls(self):
        patterns = self.config.get('AGS_CLIENT_AUTHENTICATED_URLS', '')
        patterns = patterns.split(',')
        patterns = ['^{}/?$'.format(p.strip()) for p in patterns]
        return list(map(re.compile, patterns))
