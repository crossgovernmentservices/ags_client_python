# -*- coding: utf-8 -*-
"""
AGS Client class
"""

import re
from urllib.parse import parse_qs

from ags import oidc


class Client(object):

    def __init__(self, app):
        self.app = app
        self.config = {}
        self.urls = [
        ]
        self.callback_url_pattern = re.compile(r'^oidc_cb/?$')

    def __call__(self, environ, start_response):
        flow = oidc.AuthorizationCodeFlow(self.config)

        path = environ.get('PATH_INFO', '').lstrip('/')

        if self.callback_url_pattern.match(path):
            return self._callback(environ, start_response)

        requires_authn = True

        if requires_authn:
            return self._redirect(
                start_response,
                flow.authentication_request().full_url)

        return self.app(environ, start_response)

    def _callback(self, environ, start_response):
        flow = oidc.AuthorizationCodeFlow(self.config)
        query_string = parse_qs(environ['QUERY_STRING'])
        code = query_string.get('code', [None])[0]

        if code is None:
            return self._error('400 Bad Request', 'Missing code')

        token_response = flow.request_token(code)

        self._verify_id_token(token_response['id_token'])

        environ.update({'oidc_token_data': token_response})

        return self.app(environ, start_response)

    def _verify_id_token(self, id_token):
        pass

    def authenticate_user(self, strategy=None):
        pass

    def _redirect(self, start_response, url):
        return start_response('302 Found', [('Location', url)])

    def _error(self, start_response, status, message=None):
        start_response(status, [('Content-Type', 'text/plain; charset=utf-8')])
        if message:
            return [message.encode('utf-8')]
