import collections.abc as cl_abc
import logging
from typing import Optional

import flask
import flask.typing

class App(flask.Flask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = logging.getLogger(type(self).__name__)

    def add_url_rule(
        self,
        rule: str,
        endpoint: Optional[str],
        *,
        view_func: flask.typing.RouteCallable,
        view_func_wrappers: list[cl_abc.Callable[
            [flask.typing.RouteCallable], flask.typing.RouteCallable]] = None,
        **kwargs,
    ):
        """
        Add a url rule.

        Extending Flask's functionality, a list of function wrappers can be
        supplied. These must take a view_func and return a modified view_func.
        They are applied starting with the last element, so that the first
        wrapper specified is the outermost one.
        """
        wrapped_view_func = view_func
        if view_func_wrappers:
            for wrapper in reversed(view_func_wrappers):
                wrapped_view_func = wrapper(wrapped_view_func)
        super().add_url_rule(rule, endpoint, wrapped_view_func, **kwargs)
