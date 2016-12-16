import pytest


class TestRouter(object):

    @pytest.mark.xfail
    def test_add_route(self):
        # test that routes can be added with the route decorator method
        assert False

    @pytest.mark.xfail
    def test_resolve_route(self):
        # test that the resolve method returns the expected app given specific
        # method and path inputs
        assert False

    @pytest.mark.xfail
    def test_route_request(self):
        # test that a wsgi request is routed to the expected app
        assert False
