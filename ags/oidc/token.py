# -*- coding: utf-8 -*-

from datetime import datetime
import logging

from jose import jwt


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(ch)


class InvalidIdToken(Exception):
    pass


class IdToken(object):

    def __init__(self, token, flow, **kwargs):
        self.token = token
        self.header = {}
        self.flow = flow
        self.auth_request_nonce = kwargs.get('nonce')
        self.max_age = kwargs.get('max_age')
        self._decoded = False

    def is_valid(self):
        self.decode()

        if self.token['iss'] != self.flow.broker_url:
            raise InvalidIdToken("Non-trusted issuer: {iss}".format(
                **self.token))

        if isinstance(self.token['aud'], list):

            if self.flow.client_id not in self.token['aud']:
                raise InvalidIdToken("Not in valid audiences")

            if 'azp' not in self.token:
                raise InvalidIdToken("Not in authorized parties")

        elif self.token['aud'] != self.flow.client_id:
            raise InvalidIdToken("Not valid audience")

        if 'azp' in self.token and self.token['azp'] != self.flow.client_id:
            raise InvalidIdToken("Not authorized party")

        if self.header['alg'] != self.flow.id_token_signed_response_alg:
            raise InvalidIdToken("Algorithm mismatch")

        if self.token['exp'] < datetime.utcnow() - self.flow.clock_skew:
            raise InvalidIdToken("Token expired")

        if self.id_token_too_old():
            raise InvalidIdToken(
                "Token issued in past: {}".format(self.token['iat']))

        if self.token.get('nonce') != self.auth_request_nonce:
            raise InvalidIdToken("Invalid nonce")

        self.check_auth_context_class_reference()

        if self.max_age is not None:
            if self.token['auth_time'] + self.max_age < datetime.utcnow():
                raise InvalidIdToken("Token older than max_age")

    def decode(self):
        if not self._decoded:
            logger.debug('DECODING ID TOKEN')
            self.header = jwt.get_unverified_header(self.token)
            logger.debug('header {}'.format(self.header))
            key = self.flow.get_key(self.header['kid'])
            self.token = jwt.decode(
                self.token,
                key,
                'RS256',
                audience=self.flow.client_id,
                issuer=self.flow.broker_url
            )
            self.token['exp'] = datetime.fromtimestamp(int(self.token['exp']))
            if 'iat' in self.token:
                self.token['iat'] = datetime.fromtimestamp(
                    int(self.token['iat']))
            if 'auth_time' in self.token:
                self.token['auth_time'] = datetime.fromtimestamp(
                    int(self.token['auth_time']))
            self._decoded = True

    def check_auth_context_class_reference(self):
        """
        If the acr Claim was requested, the Client SHOULD check that the
        asserted Claim Value is appropriate.
        """
        pass

    def id_token_too_old(self):
        return self.flow.id_token_max_age and \
            self.token['iat'] < datetime.utcnow() - self.flow.id_token_max_age
