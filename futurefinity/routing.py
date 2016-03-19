#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2016 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import re
import typing
import collections


class RoutingRule(collections.namedtuple(
 "RoutingRule", ("handler", "path_args", "path_kwargs"))):
    """
    Basic Routing Rule for Routing, which contains a handler, path_args,
    and a path_kwargs. It can be either a stored rule in a routing locator,
    or a matched rule that will be returned to the application.

    :arg handler: should be a ``futurefinity.web.RequestHandler`` object.
    :arg path_args: is a tuple or list that contains the positional arguments.
    :arg path_kwargs: is a dict that contains the keyword arguments.
    """

    pass


class RoutingLocator:
    """
    A Routing Locator.

    :arg default_handler: should be a ``futurefinity.web.RequestHandler``
        object, which will be returned if a handler cannot be found during the
        path matching.
    """

    def __init__(self, default_handler: typing.Optional[object]=None):
        self.handlers_dict = collections.OrderedDict()
        self.links_dict = collections.OrderedDict()
        self.default_handler = default_handler

    def add(self, path: str, handler: object, *args, name=None, **kwargs):
        """
        Add a routing rule to the locator.

        :arg path: is a regular expression of the path that will be matched.
        :arg handler: should be a ``futurefinity.web.RequestHandler``.
        :arg \*args: all the other positional arguments will be come the
            path_args of the routing rule. The arguments passed here always
            have a higher priority in the matched routing rule, which means
            that all the positional arguments passed here will be the first
            part of the matched object.
        :arg name: the name of the routing rule.
        :arg \*\*kwargs: all the other keyword arguments will be come the
            path_kwargs of the routing rule. The arguments passed here always
            have a higher priority in the matched routing rule, which means
            that if the same key also exsits in the regular expression,
            this one will override the one in the path.
        """
        if isinstance(path, str):
            path = re.compile(path)

        if name is not None:
            self.links_dict[name] = path

        self.handlers_dict[path] = RoutingRule(handler=handler,
                                               path_args=args,
                                               path_kwargs=kwargs)

    def find(self, path: str) -> RoutingRule:
        """
        Find a handler that matches the path.

        If a handler that matches the path cannot be found, the handler will be
        the default_handler.

        It returns a ``RoutingRule``.

        For the path_args and path_kwargs, the one passes though add method
        will have a higher priority.
        """
        for (key, value) in self.handlers_dict.items():
            matched_obj = key.fullmatch(path)

            if matched_obj is None:
                continue

            path_args = []
            path_args.extend(value.path_args)
            link_args = matched_obj.groups()
            if link_args is not None:
                path_args.extend(link_args)

            path_kwargs = {}
            link_kwargs = matched_obj.groupdict()
            if link_kwargs is not None:
                path_kwargs.update(link_kwargs)

            path_kwargs.update(value.path_kwargs)

            return RoutingRule(handler=value.handler,
                               path_args=path_args,
                               path_kwargs=path_kwargs)
        else:
            return RoutingRule(handler=self.default_handler,
                               path_args=(),
                               path_kwargs={})
