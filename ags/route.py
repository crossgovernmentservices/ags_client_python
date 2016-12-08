import re
from urllib.parse import urlparse


class RouteNotMatched(Exception):
    pass


class Router(object):

    def __init__(self):
        self.routes = []

    def __call__(self, environ, start_response):

        parts = urlparse(environ['PATH_INFO'])

        app = self.resolve(environ['REQUEST_METHOD'], parts.path)

        if app:
            return app(environ, start_response)

    def route(self, pattern, methods=['GET']):

        def decorator(app):
            self.routes.append((pattern, (re.compile(pattern), methods, app)))
            return app

        return decorator

    def resolve(self, method, path):
        for route, (pattern, methods, app) in self.routes:

            if method in methods and pattern.match(path):
                return app

        raise RouteNotMatched(route for route, _ in self.routes)
