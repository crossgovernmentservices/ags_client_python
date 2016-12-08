from http.cookies import SimpleCookie

from ags.logger import get_logger


class FeatureFlagMiddleware(object):

    def __init__(self, app, fallback_app, flag_name, default=True):
        self.app = app
        self.logger = get_logger(__name__)
        self.fallback_app = fallback_app
        self.flag_name = flag_name
        self.default = default
        self.url = '/toggle-feature/{}'.format(flag_name)

    def __call__(self, environ, start_response):
        cookie = self.load_cookie(environ)
        flag_state = self.current_value(cookie)

        if environ.get('PATH_INFO', '') == self.url:
            flag_state = not flag_state

            self.logger.info('Setting feature flag {flag} to {state}'.format(
                flag=self.flag_name,
                state=flag_state))

            start_response(
                '200 OK',
                [('Content-Type', 'text/plain; charset=utf-8')] +
                self.set_flag(flag_state, cookie))

            return ['{flag} feature flag set to: {state}'.format(
                flag=self.flag_name,
                state=flag_state).encode('utf-8')]

        if flag_state is True:
            return self.app(environ, start_response)

        return self.fallback_app(environ, start_response)

    def load_cookie(self, environ):
        cookie = SimpleCookie()
        cookie_header = environ.get('HTTP_COOKIE', '')
        cookie.load(cookie_header)
        return cookie

    def set_flag(self, value, cookie):
        cookie[self.flag_name] = '1' if value else '0'
        return [('Set-cookie', val.OutputString()) for val in cookie.values()]

    def current_value(self, cookie):
        value = cookie.get(self.flag_name)

        if value is None:
            return self.default

        return value.value == '1'
