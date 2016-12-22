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

"""
``futurefinity.web`` contains Application and RequestHandler class, which are
essential of building an web application based on futurefinity.

To use `futurefinity.web`,you need to import it and asyncio,
and create an instance of Application class::

  import futurefinity.web
  import asyncio

  app = futurefinity.web.Application()

Then, you need to inherit RequestHandler class to create handlers,
and override methods in the class named with HTTP methods with async def.
After that, decorate the created class with the app.add_handler with link
that this class will handle::

  @app.handlers.add("/")
  class RootHandler(futurefinity.web.RequestHandler):
      async def get(self, *args, **kwargs):
          return "Hello, World!"

Finally, listen to the port you want, and start the event loop::

  app.listen(23333)
  asyncio.get_event_loop().run_forever()

"""

from .utils import Identifier
from . import log
from . import compat
from . import server
from . import routing
from . import encoding
from . import protocol
from . import security
from . import httputils
from . import templating

from typing import Optional, Union, Mapping, List, Dict, Any, Callable

import asyncio
import asyncio.base_events

import os
import re
import ssl
import sys
import hmac
import html
import hashlib
import inspect
import warnings
import functools
import mimetypes
import traceback

_DEFAULT_MARK = Identifier()


_DEFAULT_ERROR_TPL = """
<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8">
    <title>{error_code}: {status_code_description}</title>
</head>
<body>
    <div>
        <pre>{error_code}: {status_code_description}\n\n{content}\n</pre>
    </div>
</body>
</html>
""".strip()

_DEFAULT_REDIRECT_TPL = """
<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8">
    <title>{status_code} {status_code_description}</title>
</head>
<body>
    <h1>{status_code} {status_code_description}</h1>
    The document has moved <a href="{url}">here</a>.
</body>
</html>
""".strip()

web_log = log.get_child_logger("web")
access_log = log.get_child_logger("web_access")


def print_access_log(
    request: protocol.HTTPIncomingRequest,
        status_code: int):
    """
    Print the access log.
    """
    if status_code < 400:
        log_fn = access_log.info

    elif status_code < 500:
        log_fn = access_log.warn

    else:
        log_fn = access_log.error

    if request.http_version == 10:
        http_version_text = "HTTP/1.0"

    elif request.http_version == 11:
        http_version_text = "HTTP/1.1"

    else:
        raise ValueError("Unknown HTTP Version.")

    log_msg = ("{method} {path} {http_version_text} - "
               "{status_code} {status_code_description}").format(
        method=request.method,
        path=request.origin_path,
        http_version_text=http_version_text,
        status_code=status_code,
        status_code_description=httputils.status_code_descriptions[status_code]
    )

    log_fn(log_msg)


class HTTPError(server.ServerError):
    """
    Common HTTPError class, this Error should be raised when a non-200 status
    need to be responded.

    Any additional message can be added to the response by message attribute.

    .. code-block:: python3

      async def get(self, *args, **kwargs):
          raise HTTPError(500, message='Please contact system administrator.')
    """
    def __init__(self, status_code: int=200, *args, **kwargs):
        self.status_code = status_code
        super().__init__(*args, **kwargs)

    @property
    def _err_str(self) -> compat.Text:
        return super().__str__()

    def __repr__(self) -> compat.Text:
        return "HTTPError" + repr((self.status_code, ) + self.args)

    def __str__(self) -> compat.Text:
        final_str = "HTTP {}".format(self.status_code)
        if self._err_str:
            final_str += ": {}".format(self._err_str)

        return final_str


class _ApplicationHTTPServer(server.HTTPServer):
    def __init__(self, app: "Application",
                 loop: Optional[asyncio.BaseEventLoop]=None,
                 *args, **kwargs):
        self._loop = loop or asyncio.get_event_loop()
        self.app = app

        server.HTTPServer.__init__(self, *args, **kwargs)

        self._request_handlers = {}
        self._futures = {}

    def stream_received(
        self, incoming: protocol.HTTPIncomingRequest,
            data: bytes):
        self._request_handlers[incoming].data_received(data)

    def error_received(
        self, incoming: Optional[protocol.HTTPIncomingRequest],
            exc: tuple):
        if not incoming:
            # Message is not able to be parsed, create an placeholder.
            incoming = protocol.HTTPIncomingRequest(
                method="GET",
                origin_path="/",
                http_version=11,
                headers=protocol.HTTPHeaders(),
                connection=self.connection)

        Handler = self._request_handlers.get(
            incoming,
            self.app.settings.get("DefaultHandler", NotFoundHandler))

        request_handler = Handler(
            app=self.app,
            server=self,
            request=incoming,
            path_args=[],
            path_kwargs={}
        )

        error_code = 400

        if isinstance(exc[1], protocol.ConnectionEntityTooLarge):
            error_code = 413

        async def _try_handle_exception():
            try:
                await request_handler._handle_exception(
                    exc_info=exc, status_code=error_code)

            except:
                print_access_log(request=incoming, status_code=error_code)
                web_log.exception("Error Occurred in RequestHandler.")

            finally:
                self.transport.close()
                self.connection.connection_lost()

        compat.ensure_future(_try_handle_exception(), loop=self._loop)

    def initial_received(self, incoming: protocol.HTTPIncomingRequest):
        Handler, matched_args, matched_kwargs = self.app.handlers.find(
            incoming.path)

        request_handler = Handler(
            app=self.app,
            server=self,
            request=incoming,
            path_args=matched_args,
            path_kwargs=matched_kwargs
        )

        self._request_handlers[incoming] = request_handler
        if request_handler.stream_handler:
            self.use_stream = True

    def message_received(self, incoming: protocol.HTTPIncomingRequest):
        def _future_done(coro_future: asyncio.Future):
            try:
                coro_future.result()

            except:
                print_access_log(request=incoming, status_code=500)
                web_log.exception("Error Occurred in _handle_request.")

                # System Error, Teardown the connection.
                self.transport.close()
                self.connection.connection_lost()

            else:
                print_access_log(
                    request=incoming,
                    status_code=self._request_handlers[incoming]._status_code)

            finally:
                if incoming in self._futures.keys():
                    del self._request_handlers[incoming]
                    del self._futures[incoming]

        coro_future = compat.ensure_future(
            self._request_handlers[incoming]._handle_request(),
            loop=self._loop)

        coro_future.add_done_callback(_future_done)
        self._futures[incoming] = coro_future

    def connection_lost(self, exc: tuple):
        """
        Called by Event Loop when the connection lost.
        """
        for coro_future in self._futures.values():
            coro_future.cancel()

        server.HTTPServer.connection_lost(self, exc)


class RequestHandler:
    """
    Basic Request Handler.

    This class should not be used directly, all the request handlers must
    inherit this class and override functions that represents the HTTP method.
    """

    allow_methods = ("GET", "POST", "HEAD")
    """
    Methods that FutureFinity allows, should be contained in a tuple.
    By default, FutureFinity allows GET, POST, and HEAD.
    """

    stream_handler = False

    def __init__(self, app: "Application",
                 server: _ApplicationHTTPServer,
                 request: protocol.HTTPIncomingRequest,
                 path_args: Mapping[compat.Text, compat.Text]=None,
                 path_kwargs: Mapping[compat.Text, compat.Text]=None):
        self.app = app
        self.server = server
        self.settings = self.app.settings
        self.connection = self.server.connection

        self.request = request
        self.path_args = path_args or []
        self.path_kwargs = path_kwargs or {}
        self.http_version = self.request.http_version

        self._status_code = 200
        self._headers = protocol.HTTPHeaders()
        self._cookies = httputils.HTTPCookies()
        self._response_body = bytearray()

        self.transport = None
        if self.stream_handler:
            self.transport = self.server.transport

        self._initial_written = False
        self._body_written = False
        self._finished = False

    def get_link_arg(
        self, name: compat.Text,
            default: Union[compat.Text, object]=_DEFAULT_MARK) -> compat.Text:
        """
        Return first argument in the link with the name.

        :arg name: the name of the argument.
        :arg default: the default value if no value is found. If the default
            value is not specified, it means that the argument is required, it
            will produce an error if the argument cannot be found.
        """
        arg_content = self.request.link_args.get_first(name, default)
        if arg_content is _DEFAULT_MARK:
            raise KeyError(
                "The name {} cannot be found in link args.".format(name))
        return arg_content

    def get_all_link_args(self, name: compat.Text) -> List[compat.Text]:
        """
        Return all link args with the name by list.

        If the arg cannot be found, it will return an empty list.
        """
        return self.request.queries.get_list(name, [])

    def get_body_arg(
        self, name: compat.Text,
            default: Union[compat.Text, object]=_DEFAULT_MARK) -> compat.Text:
        """
        Return first argument in the body with the name.

        :arg name: the name of the argument.
        :arg default: the default value if no value is found. If the default
            value is not specified, it means that the argument is required, it
            will produce an error if the argument cannot be found.
        """
        arg_content = self.request.body_args.get_first(name, default)
        if arg_content is _DEFAULT_MARK:
            raise KeyError(
                "The name {} cannot be found in body args.".format(name))
        return arg_content

    def get_all_body_args(self, name: compat.Text) -> List[compat.Text]:
        """
        Return all body args with the name by list.

        If the arg cannot be found, it will return an empty list.
        """
        return self.request.body_args.get_list(name, [])

    def get_header(
        self, name: compat.Text,
            default: Union[compat.Text, object]=_DEFAULT_MARK) -> compat.Text:
        """
        Return First Header with the name.

        :arg name: the name of the header.
        :arg default: the default value if no value is found. If the default
            value is not specified, it means that the header is required, it
            will produce an error if the header cannot be found.
        """
        header_content = self.request.headers.get_first(name, default)
        if header_content is _DEFAULT_MARK:
            raise KeyError(
                "The name {} cannot be found in headers.".format(name))
        return header_content

    def get_all_headers(self, name: compat.Text) -> List[compat.Text]:
        """
        Return all headers with the name by list.

        If the header cannot be found, it will return an empty list.
        """
        return self.request.headers.get_list(name, [])

    def set_header(self, name: compat.Text, value: compat.Text):
        """
        Set a response header with the name and value, this will override any
        former value(s) with the same name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot set a new header after the "
                                 "initial is written.")
        self._headers[name] = encoding.ensure_str(value)

    def add_header(self, name: compat.Text, value: compat.Text):
        """
        Add a response header with the name and value, this will not override
        any former value(s) with the same name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot add a new header after the "
                                 "initial is written.")
        self._headers.add(name, encoding.ensure_str(value))

    def clear_header(self, name: compat.Text):
        """
        Clear response header(s) with the name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot clear headers after the "
                                 "initial is written.")
        if name in self._headers.keys():
            del self._headers[name]

    def clear_all_headers(self):
        """
        Clear all response header(s).
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot clear headers after the "
                                 "initial is written.")
        self._headers = HTTPHeaders()

    def get_cookie(
        self, name: compat.Text,
            default: Optional[compat.Text]=None) -> compat.Text:
        """
        Return first Cookie in the request header(s) with the name.

        If the cookie is expired or doesn't exist, it will return the default
        value.
        """
        cookie = self.request.cookies.get(name, None)
        if cookie is None:
            return default
        return cookie.value

    def set_cookie(self, name: compat.Text, value: compat.Text,
                   domain: Optional[compat.Text]=None,
                   expires: Optional[compat.Text]=None,
                   path: compat.Text="/", expires_days: Optional[int]=None,
                   secure: bool=False, httponly: bool=False):
        """
        Set a cookie with attribute(s).

        :arg name: is the name of the cookie.
        :arg value: is the value of the cookie.
        :arg domain: is the domain of the cookie.
        :arg path: is the path of the cookie.
        :arg expires_days: is the lifetime of the cookie.
        :arg secure: is the property if the cookie can only be passed via
            https.
        :arg httponly: is the property if the cookie can only be passed by
            http.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot set a new cookie after the "
                                 "initial is written.")
        self._cookies[name] = value

        if domain is not None:
            self._cookies[name]["domain"] = domain

        if expires is not None:
            self._cookies[name]["expires"] = expires

        self._cookies[name]["path"] = path

        if expires_days is not None:
            self._cookies[name]["max-age"] = expires_days * 86400

        self._cookies[name]["secure"] = secure
        self._cookies[name]["httponly"] = httponly

    def clear_cookie(self, name: compat.Text):
        """
        Clear a cookie with the name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot clear a cookie after the "
                                 "initial is written.")
        self.set_cookie(
            name=name, value="",
            expires=httputils.format_timestamp(0))

    def clear_all_cookies(self):
        """
        Clear response cookie(s).
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot clear cookies after the "
                                 "initial is written.")
        for cookie_name in self.request.cookies.keys():
            self.clear_cookie(cookie_name)

    def get_secure_cookie(self, name: compat.Text, max_age_days: int=31,
                          default=None) -> compat.Text:
        """
        Get a secure cookie with the name, if it is valid, or None.

        By default, FutureFinity will use AES GCM Security Object as the
        backend of secure cookie.

        :arg name: is the name of the secure cookie.
        :max_age_days: is the valid length of the secure cookie, it you want it
            always be valid, please set it to None.
        :arg default: is the default value if the cookie is invalid.
        """
        if "security_secret" not in self.settings.keys():
            raise ValueError(
                "Cannot found security_secret. "
                "Please provide security_secret through Application Settings.")

        valid_length = None
        if max_age_days:
            valid_length = max_age_days * 86400

        cookie_content = self.get_cookie(name, default=None)

        if cookie_content is None:
            return default

        try:
            return self.app._sec_context.lookup_origin_text(cookie_content,
                                                            valid_length)
        except:
            return None

    def set_secure_cookie(self, name: compat.Text, value: compat.Text,
                          expires_days: int=30, **kwargs):
        """
        Set a secure cookie.

        By default, FutureFinity will use AES GCM Security Object as the
        backend of secure cookie.

        You must set a security_secret in Application Settings before

        you use this method. It can be generated by::

          futurefinity.security.get_random_str(length=32)

        Once security_secret is generated, treat it like a password,
        change security_secret will cause all secure_cookie become invalid.

        :arg name: is the name of the secure cookie.
        :arg value: is the value of the secure cookie.
        :arg expires_days: is the lifetime of the cookie.
        :arg \*\*kwargs: all the other keyword arguments will be passed to
            ``RequestHandler.set_cookie``.
        """
        if "security_secret" not in self.settings.keys():
            raise ValueError(
                "Cannot found security_secret. "
                "Please provide security_secret through Application Settings.")

        content = self.app._sec_context.generate_secure_text(value)

        self.set_cookie(
            encoding.ensure_str(name),
            encoding.ensure_str(content), expires_days=expires_days, **kwargs)

    def check_csrf_value(self):
        """
        Validate if csrf value is valid.

        FutureFinity uses a secure cookie _csrf and a body argument _csrf
        to prevent CSRF attack.

        To stop checking CSRF value, override this function and return `None`.
        """
        cookie_value = self.get_cookie("_csrf")
        form_value = self.get_body_arg("_csrf")

        if not (cookie_value and form_value):
            raise HTTPError(403)  # CSRF Value is not set.

        if not hmac.compare_digest(cookie_value, form_value):
            raise HTTPError(403)  # CSRF Value does not match.

    def set_csrf_value(self):
        """
        Set the csrf value.
        """
        if not hasattr(self, "__csrf_value"):
            self.__csrf_value = self.get_cookie("_csrf", None)
            if not self.__csrf_value:
                self.__csrf_value = security.get_random_str(32)
            self.set_cookie("_csrf", self.__csrf_value, expires_days=1)

    @property
    def _csrf_value(self):
        """
        Get the csrf value.
        """
        self.set_csrf_value()
        return self.__csrf_value

    @property
    def csrf_form_html(self) -> compat.Text:
        """
        Return a HTML form field contains _csrf value.
        """
        value = self._csrf_value
        return "<input type=\"hidden\" name=\"_csrf\" value=\"{}\">".format(
            value)

    def write(self, text: Union[compat.Text, bytes], clear_text: bool=False):
        """
        Write response body.

        If write() is called for many times, it will connect all text together.

        If it is called after the request finished, it will raise an error.
        """
        if self._finished:
            raise HTTPError(
                500, "Cannot write to request when it has already finished.")
        self._body_written = True
        if clear_text:
            self._response_body.clear()
        self._response_body += encoding.ensure_bytes(text)

    @property
    def render_string(self) -> Callable[
        [compat.Text, Optional[Mapping[compat.Text, compat.Text]]],
            compat.Text]:
        warnings.warn("RequestHandler.render_string is deprecated, \
            use RequestHandler.render_str instead.")

        return self.render_str

    def get_template_args(self) -> Dict[compat.Text, Any]:
        """
        Get the default arguments for template rendering.

        Override this function to return custom default template arguments.
        """
        return {
            "handler": self,
            "csrf_form_html": self.csrf_form_html
        }

    async def render_str(
        self, template_name: compat.Text,
        template_dict: Optional[
            Mapping[compat.Text, compat.Text]]=None) -> compat.Text:
        """
        Render Template in template folder into string.

        You can Specify Template Engine by overriding this function.
        """

        template_args = self.get_template_args()

        template_args.update(**template_dict)

        if "template_path" not in self.settings.keys():
            raise ValueError(
                "Cannot found `template_path`. "
                "Please provide `template_path` through Application Settings.")

        parsed_tpl = await self.app._tpl_loader.load_tpl(
            template_name)
        return await parsed_tpl.render_str(**template_args)

    async def render(
        self, template_name: compat.Text,
            template_dict: Mapping[compat.Text, compat.Text]={}):
        """
        Render the template with render_str, and write them into response
        body directly.
        """
        self.finish(
            await self.render_str(
                template_name, template_dict=template_dict))

    def redirect(self, url: compat.Text, permanent: bool=False,
                 status: Optional[int]=None):
        """
        Rediect request to other location.

        :arg url: is the relative url or absolute url that the client will be
            redirected to.
        :arg permanent: True if this is 301 or 302.
        :arg status: Custom the status code.
        """
        if self._initial_written:
            raise HTTPError(400, "Cannot redirect after initial written.")
        if status is None:
            status = 301 if permanent else 302
        else:
            assert isinstance(status, int) and 300 <= status <= 399
        self._status_code = status
        self.set_header("location", url)
        self.finish(_DEFAULT_REDIRECT_TPL.format(
            status_code=status,
            status_code_description=httputils.status_code_descriptions[status],
            url=url))

    def set_body_etag(self):
        """
        Set etag header of response_body.
        """
        if not hasattr(self, "_prepared_body_etag"):
            sha1_hash_object = hashlib.sha1()
            sha1_hash_object.update(self._response_body)

            self._prepared_body_etag = '"{}"'.format(
                sha1_hash_object.hexdigest())
            if self._prepared_body_etag is not '""':
                self.set_header("etag", self._prepared_body_etag)

    @property
    def _body_etag(self) -> compat.Text:
        """
        Return the etag of the body.
        """
        self.set_body_etag()
        return self._prepared_body_etag

    def check_body_etag(self) -> bool:
        """
        Check etag header of response_body.
        """
        computed_etag = encoding.ensure_bytes(self._body_etag)
        etags = re.findall(
            br'\*|(?:W/)?"[^"]*"',
            encoding.ensure_bytes(self.get_header("if-none-match", ""))
        )
        if not computed_etag or not etags:
            return False

        match = False
        if etags[0] == b'*':
            match = True
        else:
            def value_validator(value):
                if value.startswith(b'W/'):
                    value = value[2:]
                return value
            for etag in etags:
                if value_validator(etag) == value_validator(computed_etag):
                    match = True
                    break
        return match

    def when_write_initial(self):
        """
        Triggered when writing the initial.

        This can be a coroutine, however, if this is a coroutine, it will not
        block writing the initial.
        """
        pass

    def write_initial(self):
        """
        Send the Initial Part(e.g.: Headers) of a Response to the remote.

        This function should be only called once.

        Usually this function is called by `RequestHandler.flush`
        automatically.

        After this function is called, you cannot add any new headers, cookies,
        or change the status_code. If an error is raised after this function
        is called, FutureFinity is going to close the connection directly.
        """
        if self._initial_written:
            raise HTTPError(500, "Cannot write the initial twice.")

        when_write_initial_result = self.when_write_initial()

        if inspect.isawaitable(when_write_initial_result):
            compat.ensure_future(when_write_initial_result, loop=self._loop)

        if "content-type" not in self._headers.keys():
            self.set_header("content-type", "text/html; charset=utf-8;")

        if self.connection._can_keep_alive:
            if "connection" not in self._headers:
                self.set_header("connection", "Keep-Alive")
        else:
            self.set_header("connection", "Close")

        if self._headers["connection"] == "Keep-Alive":
            self.set_header("transfer-encoding", "Chunked")
            if "content-length" in self._headers.keys():
                del self._headers["content-length"]

        if "date" not in self._headers.keys():
            self.set_header("date", httputils.format_timestamp())

        self._headers.accept_cookies_for_response(self._cookies)

        if self.settings.get("csrf_protect", False):
            self.set_csrf_value()

        self.connection.write_initial(
            http_version=self.http_version,
            status_code=self._status_code, headers=self._headers)

        self._initial_written = True

    def flush(self):
        """
        Flush the request to the remote.
        """
        if self._finished:
            raise HTTPError(
                500, "Cannot Flush the request when it has already finished.")

        if not self._initial_written:
            self.write_initial()

        if not self._body_written:
            raise HTTPError(500, "Body is not written.")
        self.connection.write_body(self._response_body)
        self._response_body.clear()

    def when_finish(self):
        """
        Triggered when finishing the request.

        This can be a coroutine, however, if this is a coroutine, it will not
        block finishing the request.
        """
        pass

    def finish(self, text: Optional[Union[compat.Text, bytes]]=None):
        """
        Finish the request, send the response. If a text is passed, it will be
        write first, after that, the request will be finished.

        If it is called more than one time, it will raise an error.
        """
        if self._finished:
            raise HTTPError(
                500, "Cannot Finish the request when it has already finished.")

        when_finish_result = self.when_finish()

        if inspect.isawaitable(when_finish_result):
            compat.ensure_future(when_finish_result, loop=self._loop)

        if text is not None:
            self.write(text)

        if self._initial_written is False:
            if ("etag" not in self._headers and
                self._status_code == 200 and
                    self.request.method in ("GET", "HEAD")):
                self.set_body_etag()

            if self.check_body_etag():
                self._status_code = 304
                self._response_body.clear()
                for header_name in ("allow", "content-encoding",
                                    "content-language", "content-length",
                                    "content-md5", "content-range",
                                    "content-type", "last-modified"):
                    self.clear_header(header_name)

        self.flush()
        self._finished = True

        self.connection.finish_writing()

    async def write_error(self, error_code: int,
                          message: Optional[Union[compat.Text, bytes]]=None,
                          exc_info: Optional[tuple]=None):
        """
        Write the error message to the client.

        You may override this page if you want to custom the error page.

        However, if it raises an error again, the connection will be closed
        immediately without write anything to the client.
        """
        self._status_code = error_code
        self.set_header("Content-Type", "text/html; charset=utf-8")

        if self._status_code >= 400:
            self.set_header("Connection", "Close")

        content = ""

        if message:
            content += html.escape(encoding.ensure_str(message)) + "\n\n"

        if self.settings.get("debug", False) and exc_info:
            content += html.escape(
                "\n".join(traceback.format_exception(*exc_info))) + "\n\n"

        self.write(
            _DEFAULT_ERROR_TPL.format(
                error_code=error_code,
                status_code_description=httputils.status_code_descriptions[
                    error_code],
                content=content),
            clear_text=True)

        self.finish()

    async def before(self):
        """
        Triggered before the actual method function starts to
        handle the request.

        **This is a Coroutine.**
        """
        pass

    async def head(self, *args, **kwargs):
        """
        Respond the Head Request.

        **This is a Coroutine.**
        """
        get_return_text = await self.get(*args, **kwargs)
        if self._status_code != 200:
            return
        if self._body_written is True:
            content_length = len(self._response_body)
        else:
            content_length = len(get_return_text)
        if not self.connection._can_keep_alive:
            self.set_header("content-length", str(content_length))
        self.write(b"", clear_text=True)

    async def get(self, *args, **kwargs):  # pragma: no cover
        """
        Must be overridden in subclass if you want to handle GET request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def post(self, *args, **kwargs):  # pragma: no cover
        """
        Must be overridden in subclass if you want to handle POST request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def delete(self, *args, **kwargs):  # pragma: no cover
        """
        Must be overridden in subclass if you want to handle DELETE request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def patch(self, *args, **kwargs):  # pragma: no cover
        """
        Must be overridden in subclass if you want to handle PATCH request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def put(self, *args, **kwargs):  # pragma: no cover
        """
        Must be overridden in subclass if you want to handle PUT request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def options(self, *args, **kwargs):  # pragma: no cover
        """
        Must be overridden in subclass if you want to handle OPTIONS request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def _handle_exception(
        self, exc_info: Optional[tuple]=None,
            status_code: Optional[int]=None):
        """
        Method to handle the exception.

        It checks the connection status, write the traceback and web log, and
        write the error pages.

        **This is a Coroutine.**
        """

        if self._initial_written:
            return
            # Cannot Write the exception the request because of the initial has
            # already been written.
            # The server cannot withdraw the written data from the client.

        if exc_info:
            err = exc_info[1]

            if self.settings.get("debug", False):
                log_str = str(self.request)

            else:
                log_str = ""

            if isinstance(err, HTTPError):
                status_code = status_code or err.status_code
                message = err._err_str

                if err.status_code < 400:
                    web_log.info(log_str, exc_info=exc_info)

                elif exc_info[1].status_code < 500:
                    web_log.warn(log_str, exc_info=exc_info)

                else:
                    web_log.error(log_str, exc_info=exc_info)

            else:
                status_code = status_code or 500
                message = None

                web_log.error(log_str, exc_info=exc_info)

        else:
            status_code = status_code or 500
            message = None

        err_result = self.write_error(status_code, message, exc_info)
        if inspect.isawaitable(err_result):
            await err_result

    async def _handle_request(self):
        """
        Method to handle the request.

        It checks the if request method is supported and allowed, handles
        them to right class function, gets the return value, writes them to
        response body, and finishes the request.

        **This is a Coroutine.**
        """
        try:
            if self.request.method not in self.allow_methods:
                raise HTTPError(405)
            if self.settings.get("csrf_protect", False
                                 ) and self.request._body_expected is True:
                self.check_csrf_value()

            await self.before()

            body = await getattr(self, self.request.method.lower())(
                *self.path_args, **self.path_kwargs)

            if not self._body_written:
                self.write(body)

        except:
            await self._handle_exception(sys.exc_info())

        if not self._finished:
            self.finish()

    def data_received(self):  # pragma: no cover
        """
        For StreamRequestHandler. If you use this as a stream handler, you
        must overrride this function.
        """
        raise NotImplementedError


class NotFoundHandler(RequestHandler):
    """
    Default RequestHandler when link matches no handler.

    By default, it just returns a 404 Error to the client.
    """
    async def get(self, *args, **kwargs):
        raise HTTPError(404)

    # By default, FutureFinity only allows ("HEAD", "GET", and "POST")
    post = get


class StaticFileHandler(RequestHandler):
    """
    Handler that handles static files.

    Warning: You should use Web Server(such as: Nginx) to handle Static Files.
             StaticFileHandler should only be used in development.
    """

    static_path = None  # Modify this to custom static path for this handler.

    async def handle_static_file(
            self, file_uri_path: compat.Text, *args, **kwargs):
        """
        Get the file from the given file path. Override this function if you
        want to customize the way to get file.
        """
        if not self.static_path:
            self.static_path = self.settings.get("static_path", "statics")
        file_path = os.path.join(self.static_path, file_uri_path)

        if not os.path.realpath(file_path).startswith(
         os.path.realpath(self.static_path)):
            raise HTTPError(403)

        if not os.path.exists(file_path):
            raise HTTPError(404)

        if os.path.isdir(file_path):
            raise HTTPError(403)

        file_size = os.path.getsize(file_path)
        if file_size >= 1024 * 1024 * 50:
            # StaticFileHandler Currently does not support
            # file bigger than 50MB.
            raise HTTPError(500, "Static File Size Too Large.")

        mime = mimetypes.guess_type(file_uri_path)[0]
        mime = mime or "application/octet-stream"
        self.set_header("content-type", mime)

        with open(file_path, "rb") as f:
            self.finish(f.read())

    async def get(self, *args, **kwargs):
        await self.handle_static_file(file_uri_path=kwargs["file"])


class Application:
    """
    Class that its instance creates asyncio compatible servers,
    stores handler list, finds every request's handler,
    and passes it to server.

    :arg loop: A Custom EventLoop, or FutureFinity will use the result of
      `asyncio.get_event_loop()`.
    :arg template_path: The default template_path.
      This will also initialize the default template loader if it is set.
    :arg security_secret: The secret for security purpose.
      Treat it like a password. If the secret is changed, all secure cookies
      will become invalid. This will also initialize the default
      security object if it is set.
    :arg cache_template: The default value is reverse of debug option.
      See :class:`futurefinity.templating.loader.BaseLoader`
      for more details.
    :arg default_escape: Default: `"html"`.
      See :class:`futurefinity.templating.loader.BaseLoader`
      for more details.
    :arg escape_url_with_plus: Default: `True`.
      See :class:`futurefinity.templating.loader.BaseLoader`
      for more details.
    :arg allow_keep_alive: Default: `True`.
      Allow Keep Alive or not. This attribute will be passed to
      :class:`futurefinity.server.HTTPServer` as an attribute.
    :arg DefaultHandler: Default: :class:`.NotFoundHandler`.
      Default handler when no path is matched.
    :arg debug: Enable Debug Feature.
    :arg csrf_protect: Enable Cross Site Request Forgeries(CSRF) protection.
    :arg static_path: Add a default static file handler with the static path.
    :arg static_handler_path: Default: `r"/statics/(?P<file>.*?)"`.
      This is an regualr expression that indicates routing path will be used
      for the default static file handler. The attribute `file` in the
      regualr expression will be passed to the default static file handler.

    :arg \*\*kwargs: All the other keyword arguments will be in the application
      settings too.
    """
    def __init__(self, **kwargs):
        self.settings = kwargs
        self._loop = self.settings.get(
            "loop", asyncio.get_event_loop())  # type: asyncio.BaseEventLoop

        self.handlers = routing.Dispatcher(
            DefaultHandler=self.settings.get(
                "DefaultHandler", NotFoundHandler))

        self._tpl_loader = None
        self._sec_context = None

        if "template_path" in self.settings.keys():
            tpl_context = templating.TemplateContext(
                cache_tpls=self.settings.get(
                    "cache_template", (not self.settings.get("debug", False))),
                default_escape="html",
                input_encoding="utf-8", output_encoding="utf-8",
                escape_url_with_plus=True,
                loop=self._loop)

            self._tpl_loader = templating.AsyncFileSystemLoader(
                self.settings["template_path"],
                tpl_context)

        if "security_secret" in self.settings.keys():
            if "aes_security" in self.settings.keys():
                warnings.warn(
                    "aes_security option is deprecated. "
                    "To ensure security, AESContext should always be used.",
                    DeprecationWarning)

                if self.settings.get("aes_security", True):
                    self._sec_context = security.AESContext(
                        self.settings["security_secret"])

                else:
                    self._sec_context = security.HMACSecurityContext(
                        self.settings["security_secret"])

            else:
                self._sec_context = security.AESContext(
                        self.settings["security_secret"])

        if "static_path" in self.settings.keys():
            static_handler_path = self.settings.get("static_handler_path",
                                                    r"/statics/(?P<file>.*?)")

            self.handlers.add(static_handler_path, Handler=StaticFileHandler)

    @property
    def template_loader(self) -> templating.AsyncFileSystemLoader:
        """
        .. deprecated:: 0.3
            For direct access to `TemplateLoader`.
            Use `Application._tpl_loader` instead.
        """
        warnings.warn(
            "`Application.template_loader` is deprecated. "
            "Use `Application._tpl_loader` instead.",
            DeprecationWarning)

        return self._tpl_loader

    @property
    def security_object(self) -> security.BaseContext:
        """
        .. deprecated:: 0.3
            For direct access to `SecurityContext`.
            Use `Application._sec_context` instead.
        """
        warnings.warn(
            "`Application.security_object` is deprecated. "
            "Use `Application._sec_context` instead.",
            DeprecationWarning)

        return self._sec_context

    def make_server(self) -> asyncio.Protocol:  # type: ignore
        """
        Make a asyncio compatible server.
        """
        return functools.partial(
            _ApplicationHTTPServer, app=self, loop=self._loop,
            allow_keep_alive=self.settings.get("allow_keep_alive", True))

    def listen(
        self, port: int, address: compat.Text="127.0.0.1",
        context: Optional[Union[bool, ssl.SSLContext]]=None
            ) -> compat.Awaitable[asyncio.base_events.Server]:
        """
        Make the server to listen to the specified port and address.

        :arg port: The port number that futurefinity is going to bind.
        :arg address: the address that futurefinity is going to bind.
        :arg context: The TLS Context used to the server.
        """
        if context:
            if isinstance(context, bool):
                context = ssl.create_default_context()
        else:
            context = None
        f = self._loop.create_server(self.make_server(), address, port,
                                     ssl=context)
        srv = compat.ensure_future(f, loop=self._loop)
        return srv

    @property
    def add_handler(self) -> Callable[[Any], Optional[RequestHandler]]:
        """
        .. deprecated:: 0.3
            This method is deprecated. Use `Application.handlers.add` instead.

        Add a handler to handler list.
        """
        warnings.warn(
            "`Application.add_handler` is deprecated. "
            "Use `Application.handlers.add` instead.",
            DeprecationWarning)

        return self.handlers.add
