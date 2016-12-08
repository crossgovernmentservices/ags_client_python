# -*- coding: utf-8 -*-
"""
Test the feature switch enabling/disabling the AGS middleware
"""

import pytest

from ags.feature_flag import FeatureFlagMiddleware


def app1(environ, start_response):
    start_response("302 Found", [('Content-Type', 'text/plain')])
    return ['app']


def app2(environ, start_response):
    start_response("404 Not Found", [('Content-Type', 'text/plain')])
    return ['fallback']


@pytest.fixture
def wsgi_app():
    return FeatureFlagMiddleware(app1, app2, 'test-flag')


@pytest.fixture
def request(wsgi_app, wsgi_request):

    def make_request(url, data=None, headers={}):
        return wsgi_request(wsgi_app, url, data=data, headers=headers)

    return make_request


class TestFeatureSwitch(object):

    def test_app_invoked_when_feature_switch_activated(self, request):
        headers = {'HTTP_COOKIE': 'test-flag=1'}
        status, headers, response = request('/foo', headers=headers)
        assert status == '302 Found'
        assert 'app' in response

    def test_fallback_when_feature_switch_deactivated(self, request):
        headers = {'HTTP_COOKIE': 'test-flag=0'}
        status, headers, response = request('/foo', headers=headers)
        assert status == '404 Not Found'
        assert 'fallback' in response

    def test_feature_switch_activate_url(self, request):
        headers = {'HTTP_COOKIE': 'test-flag=0'}
        status, headers, response = request(
            '/toggle-feature/test-flag', headers=headers)
        assert status == '200 OK'
        assert ('Set-cookie', 'test-flag=1') in headers

    def test_flag_defaults_to_specified_value(self, request):
        # test-flag defaults to True
        status, headers, response = request('/toggle-feature/test-flag')
        assert ('Set-cookie', 'test-flag=0') in headers
