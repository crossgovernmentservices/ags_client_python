from datetime import datetime
from http.cookies import SimpleCookie
import mock
from wsgiref.util import setup_testing_defaults

import pytest


@pytest.fixture
def cookie_jar():
    return {}


@pytest.fixture
def wsgi_request(cookie_jar):

    def make_request(wsgi_app, url, data=None, headers={}):
        path, _, query = url.partition('?')
        environ = {
            'PATH_INFO': path,
            'QUERY_STRING': query,
            'REQUEST_METHOD': 'GET' if data is None else 'POST'}
        setup_testing_defaults(environ)
        environ.update(headers)

        cookies = environ.get('HTTP_COOKIE', [])
        if cookies:
            cookies = cookies.split(';')
        for key, val in cookie_jar.items():
            cookies.append('{}={}'.format(key.strip(), val.strip()))
        environ['HTTP_COOKIE'] = ';'.join(cookies)

        start_response = mock.MagicMock()
        response = wsgi_app(environ, start_response)
        calls = start_response.mock_calls
        status = calls[0][1][0]
        headers = calls[0][1][1]

        for header, val in headers:
            if header == 'Set-cookie':
                cookie = SimpleCookie()
                cookie.load(val)
                key = list(cookie.keys())[0]
                value = list(cookie.values())[0]
                expires = value['expires']
                if expires:
                    expires = datetime.strptime(
                        expires, '%a, %d-%b-%Y %H:%M:%S %Z')
                if expires and expires < datetime.now():
                    if key in cookie_jar:
                        del cookie_jar[key]
                else:
                    cookie_jar[key] = value.value

        return status, headers, response

    return make_request
