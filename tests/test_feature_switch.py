# -*- coding: utf-8 -*-
"""
Test the feature switch enabling/disabling the AGS middleware
"""


class TestFeatureSwitch(object):

    def test_passthru_when_feature_switch_deactivated(self, wsgi_request):
        status, headers, response = wsgi_request('/foo')
        assert status == '200 OK'

    def test_feature_switch_activate_url(self, wsgi_request):
        status, headers, response = wsgi_request('/ags-toggle-feature-switch')
        assert status == '200 OK'
        assert ('Set-cookie', 'ags_feature_switch_active=1') in headers

    def test_auth_when_feature_switch_activated(self, wsgi_request):
        req_headers = {'HTTP_COOKIE': 'ags_feature_switch_active=1'}
        status, headers, response = wsgi_request('/foo', headers=req_headers)
        print(headers)
        print(response)
        assert status == '302 Found'
