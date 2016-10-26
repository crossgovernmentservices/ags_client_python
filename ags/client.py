# -*- coding: utf-8 -*-
"""
AGS Client class
"""

from base64 import (
    urlsafe_b64decode as b64decode,
    urlsafe_b64encode as b64encode)
import json
import logging
import os
import re
from urllib.parse import parse_qs
from wsgiref.util import request_uri

from beaker.middleware import SessionMiddleware
from cached_property import cached_property, threaded_cached_property

from ags import oidc


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

    def wsgi_app(self, environ, start_response):

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

    def callback(self, environ, start_response):
        code = self.authorization_code(environ)
        state = self.callback_state(environ)

        self.logger.debug('received authz code {}'.format(code))
        self.logger.debug('received state {}'.format(state))

        if code is None:
            return self.error('400 Bad Request', 'Missing code')

        token_response = self.token_request(code)
        self.logger.debug('received token response {}'.format(token_response))
        self.verify_id_token(token_response['id_token'])

        session = environ['beaker.session']
        session['authenticated'] = True
        session['oidc_token_data'] = token_response
        session.save()

        if state and 'next_url' in state:
            return self.redirect(start_response, state['next_url'])

        return self.app(environ, start_response)

    def verify_id_token(self, id_token):
        # TODO
        pass

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

    def error(self, start_response, status, message=None):
        start_response(status, [('Content-Type', 'text/plain; charset=utf-8')])
        if message:
            return [message.encode('utf-8')]

    @property
    def flow(self):
        return oidc.AuthorizationCodeFlow(self.config)

    def is_callback(self, environ):
        return self.callback_url_pattern.match(self.request_path(environ))

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
        session = environ.get('beaker.session')

        if session and 'authenticated' in session:
            return session['authenticated']

    @threaded_cached_property
    def authenticated_urls(self):
        patterns = self.config.get('AGS_CLIENT_AUTHENTICATED_URLS', '')
        patterns = patterns.split(',')
        patterns = ['^{}/?$'.format(p.strip()) for p in patterns]
        return list(map(re.compile, patterns))
