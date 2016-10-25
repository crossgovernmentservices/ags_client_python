# -*- coding: utf-8 -*-
"""
AGS Client class
"""

import re
from urllib.parse import parse_qs

from cached_property import threaded_cached_property

from ags import oidc


class Client(object):

    def __init__(self, app):
        self.app = app
        self.config = {}

    def __call__(self, environ, start_response):
        path = self.request_path(environ)

        if self.callback_url_pattern.match(path):
            return self.callback(environ, start_response)

        if self.requires_authentication(path):
            return self.redirect(start_response, self.authentication_request)

        return self.app(environ, start_response)

    def callback(self, environ, start_response):
        code = self.authorization_code(environ)

        if code is None:
            return self.error('400 Bad Request', 'Missing code')

        token_response = self.token_request(code)
        self.verify_id_token(token_response['id_token'])
        environ.update({'oidc_token_data': token_response})

        return self.app(environ, start_response)

    def verify_id_token(self, id_token):
        # TODO
        pass

    def requires_authentication(self, path):
        for url_pattern in self.whitelisted_urls:

            if url_pattern.match(path):
                return False

        return True

    @property
    def authentication_request(self):
        return self.flow.authentication_request().full_url

    def authorization_code(self, environ):
        query_string = parse_qs(environ['QUERY_STRING'])
        return query_string.get('code', [None])[0]

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

    def redirect(self, start_response, url):
        return start_response('302 Found', [('Location', url)])

    def request_path(self, environ):
        return environ.get('PATH_INFO', '').lstrip('/')

    def token_request(self, code):
        return self.flow.request_token(code)

    @threaded_cached_property
    def whitelisted_urls(self):
        patterns = self.config.get('AGS_CLIENT_WHITELISTED_URLS', [])
        return list(map(re.compile, patterns))
