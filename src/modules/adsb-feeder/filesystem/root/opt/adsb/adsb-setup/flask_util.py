import collections.abc as cl_abc
import logging
import re
from typing import Optional

import flask
import flask.typing
from flask import redirect, request

import config


class App(flask.Flask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = logging.getLogger(type(self).__name__)

    def add_url_rule(
            self, rule: str, endpoint: Optional[str], *,
            view_func: flask.typing.RouteCallable, view_func_wrappers: list[
                cl_abc.Callable[[flask.typing.RouteCallable],
                                flask.typing.RouteCallable]] = None, **kwargs):
        wrapped_view_func = view_func
        if view_func_wrappers:
            for wrapper in reversed(view_func_wrappers):
                wrapped_view_func = wrapper(wrapped_view_func)
        super().add_url_rule(rule, endpoint, wrapped_view_func, **kwargs)

    def _make_proxy_route_specs(self, conf: config.Config):
        for endpoint, port_key_path, path in [
            ["/map/", "ports.tar1090", "/"],
            ["/tar1090/", "ports.tar1090", "/"],
            ["/graphs1090/", "ports.tar1090", "/graphs1090/"],
            ["/graphs/", "ports.tar1090", "/graphs1090/"],
            ["/stats/", "ports.tar1090", "/graphs1090/"],
            ["/fa/", "ports.piamap", "/"],
            ["/fa-status/", "ports.piastat", "/"],
            ["/fa-status.json/", "ports.piastat", "/status.json"],
            ["/fr24/", "ports.fr", "/"],
            ["/fr24-monitor.json/", "ports.fr", "/monitor.json"],
            ["/planefinder/", "ports.pf", "/"],
            ["/planefinder-stat/", "ports.pf", "/stats.html"],
            ["/dump978/", "ports.uat", "/skyaware978/"],
            ["/logs/", "ports.dazzle", "/"],
            ["/dozzle/<sub_path>", "ports.dazzle", "/"],
            ["/config/", "ports.dazzle", "/setup"],
            ["/ais-catcher/", "ports.aiscatcher", "/"],]:
            port = conf.get(port_key_path)
            yield endpoint, port, path

    def add_proxy_routes(self, conf: config.Config):
        for endpoint, port, url_path in self._make_proxy_route_specs(conf):
            r = self._function_factory(endpoint, port, url_path)
            self.add_url_rule(endpoint, endpoint, view_func=r)

    def _function_factory(self, orig_endpoint, port, new_path):
        def f(sub_path=""):
            return self._my_redirect(orig_endpoint, port, new_path, sub_path=sub_path)

        return f

    def _my_redirect(self, orig, port, new_path, sub_path=""):
        host_url = request.host_url.rstrip("/ ")
        host_url = re.sub(":\\d+$", "", host_url)
        new_path += sub_path
        q: str = ""
        if request.query_string:
            q = f"?{request.query_string.decode()}"
        url = f"{host_url}:{port}{new_path}{q}"
        self._logger.info(f"Redirecting {orig} to {url}.")
        return redirect(url)
