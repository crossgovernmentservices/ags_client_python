# -*- coding: utf-8 -*-
"""
AGS Client class
"""

from ags import oidc


class Client(object):

    def __init__(self):
        pass

    def authenticate_user(self, strategy=None):

        if strategy is None:
            strategy = oidc.AuthorizationCodeFlow()

        return strategy.authenticate_user()
