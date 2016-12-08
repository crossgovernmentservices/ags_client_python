# -*- coding: utf-8 -*-
"""
AGS Client class
"""

import os

from ags.feature_flag import FeatureFlagMiddleware
from ags.logger import get_logger
from ags.oidc_client import OIDCAuthMiddleware, OIDCClientError


class ClientError(object):

    def __init__(self, exception):
        self.exception = exception

    def __call__(self, environ, start_response):
        start_response(
            '500 Internal Error',
            [('Content-Type', 'text/plain; charset=utf-8')])
        return [str(self.exception).encode('utf-8')]


class Client(object):

    def __init__(self, app, config={}):
        self.load_config(config)

        self.logger = get_logger(__name__)

        self.app = OIDCAuthMiddleware(app, self.config)

        self.app = FeatureFlagMiddleware(
            self.app,
            app,
            flag_name=config.get('FEATURE_FLAG_COOKIE', 'ags_client_active'),
            default=config.get('FEATURE_FLAG_DEFAULT', True))

        self.debug = config.get('DEBUG', os.environ.get('DEBUG', False))

        if self.debug:
            from werkzeug.debug import DebuggedApplication
            self.app = DebuggedApplication(self.app, evalex=True)

    def load_config(self, config={}):
        self.config = {}
        for key, val in os.environ.items():
            if key.startswith('AGS_CLIENT_'):
                self.config[key[11:]] = val
        self.config.update(config)

    def __call__(self, environ, start_response):

        try:
            return self.app(environ, start_response)

        except OIDCClientError as oidc_error:
            if not self.debug:
                return ClientError(oidc_error)(environ, start_response)
            raise
