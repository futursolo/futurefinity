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

To use futurefinity.web,you need to import it and asyncio,
and create an instance of Application class::

  import futurefinity.web
  import asyncio

  app = futurefinity.web.Application()

Then, you need to inherit RequestHandler class to create handlers,
and override methods in the class named with HTTP methods with async def.
After that, decorate the created class with the app.add_handler with link
that this class will handle::

  @app.add_handler("/")
  class RootHandler(futurefinity.web.RequestHandler):
      async def get(self, *args, **kwargs):
          return "Hello, World!"

Finally, listen to the port you want, and start asyncio event loop::

  app.listen(23333)
  asyncio.get_event_loop().run_forever()

"""

from .utils import (ensure_str, ensure_bytes, format_timestamp, default_mark)
from . import server
from . import routing
from . import protocol
from . import templating
from . import security

from types import CoroutineType
from typing import Optional, Union, Mapping, List, Dict, Any, Callable

import futurefinity

import asyncio

import os
import re
import ssl
import sys
import hmac
import html
import hashlib
import warnings
import functools
import mimetypes
import traceback


_DEFAULT_ERROR_TPL = """
<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8">
    <title>{error_code}: {status_code_detail}</title>
</head>
<body>
    <div><pre>{error_code}: {status_code_detail}\n\n{content}\n</pre></div>
</body>
</html>
""".strip()

_DEFAULT_REDIRECT_TPL = """
<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8">
    <title>{status_code} {status_message}</title>
</head>
<body>
    <h1>{status_code} {status_message}</h1>
    The document has moved <a href="{url}">here</a>.
</body>
</html>
""".strip()


class HTTPError(server.ServerError):
    """
    Common HTTPError class, this Error should be raised when a non-200 status
    need to be responded.

    Any additional message can be added to the response by message attribute.

    .. code-block:: python3

      async def get(self, *args, **kwargs):
          raise HTTPError(500, message='Please contact system administrator.')
    """
    def __init__(self, status_code: int=200, message: str=None,
                 *args, **kwargs):
        self.status_code = status_code
        self.message = message


class ApplicationHTTPServer(server.HTTPServer):
    def __init__(self, app: "Application",
                 loop: Optional[asyncio.BaseEventLoop]=None,
                 *args, **kwargs):
        self._loop = loop or asyncio.get_event_loop()
        self.app = app

        server.HTTPServer.__init__(self, *args, **kwargs)

        self._request_handlers = {}
        self._futures = {}

    def stream_received(self, incoming: protocol.HTTPIncomingRequest,
                        data: bytes):
        self._request_handlers[incoming].data_received(data)

    def error_received(self,
                       incoming: Optional[protocol.HTTPIncomingRequest],
                       exc: tuple):
        if self.settings.get("debug", False) and exc:
            traceback.print_exception(*exc)

        if not incoming:  # Message unable to parse, create an placeholder.
            incoming = protocol.HTTPIncomingRequest(
                method="GET",
                origin_path="/",
                http_version=11,
                headers=protocol.HTTPHeaders(),
                connection=self.connection)
        handler = self.app.settings.get("default_handler", NotFoundHandler)
        request_handler = handler(
            app=self.app,
            server=self,
            request=incoming,
            path_args=[],
            path_kwargs={}
        )
        error_code = 400
        if isinstance(exc[1], protocol.ConnectionEntityTooLarge):
            error_code = 413
        request_handler.write_error(error_code)
        request_handler.finish()

    def initial_received(self, incoming: protocol.HTTPIncomingRequest):
        matched_obj = self.app.handlers.find(incoming.path)
        request_handler = matched_obj.handler(
            app=self.app,
            server=self,
            request=incoming,
            path_args=matched_obj.path_args,
            path_kwargs=matched_obj.path_kwargs
        )
        self._request_handlers[incoming] = request_handler
        if request_handler.stream_handler:
            self.use_stream = True

    def message_received(self, incoming: protocol.HTTPIncomingRequest):
        def _future_done(coro_future):
            if incoming in self._futures.keys():
                del self._request_handlers[incoming]
                del self._futures[incoming]
        coro_future = self._loop.create_task(
            self._request_handlers[incoming]._handle_request())
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

    This class should not be used directly, subclass must inherit this class
    and override functions that represents the HTTP method.
    """

    allow_methods = ("GET", "POST", "HEAD")
    """
    Methods that FutureFinity allows, should be contained in a tuple.
    By default, FutureFinity allows GET, POST, and HEAD.
    """

    stream_handler = False

    def __init__(self, app: "Application",
                 server: ApplicationHTTPServer,
                 request: protocol.HTTPIncomingRequest,
                 path_args: Mapping[str, str]=None,
                 path_kwargs: Mapping[str, str]=None):
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
        self._cookies = protocol.HTTPCookies()
        self._response_body = bytearray()

        self.transport = None
        if self.stream_handler:
            self.transport = self.server.transport

        self._initial_written = False
        self._body_written = False
        self._finished = False

    def get_link_arg(self, name: str,
                     default: Union[str, object]=default_mark) -> str:
        """
        Return first argument in the link with the name.

        :arg name: the name of the argument.
        :arg default: the default value if no value is found. If the default
            value is not specified, it means that the argument is required, it
            will produce an error if the argument cannot be found.
        """
        arg_content = self.request.link_args.get_first(name, default)
        if arg_content is default_mark:
            raise KeyError(
                "The name {} cannot be found in link args.".format(name))
        return arg_content

    def get_all_link_args(self, name: str) -> List[str]:
        """
        Return all link args with the name by list.

        If the arg cannot be found, it will return an empty list.
        """
        return self.request.queries.get_list(name, [])

    def get_body_arg(self, name: str,
                     default: Union[str, object]=default_mark) -> str:
        """
        Return first argument in the body with the name.

        :arg name: the name of the argument.
        :arg default: the default value if no value is found. If the default
            value is not specified, it means that the argument is required, it
            will produce an error if the argument cannot be found.
        """
        arg_content = self.request.body_args.get_first(name, default)
        if arg_content is default_mark:
            raise KeyError(
                "The name {} cannot be found in body args.".format(name))
        return arg_content

    def get_all_body_args(self, name: str) -> List[str]:
        """
        Return all body args with the name by list.

        If the arg cannot be found, it will return an empty list.
        """
        return self.request.body_args.get_list(name, [])

    def get_header(self, name: str,
                   default: Union[str, object]=default_mark) -> str:
        """
        Return First Header with the name.

        :arg name: the name of the header.
        :arg default: the default value if no value is found. If the default
            value is not specified, it means that the header is required, it
            will produce an error if the header cannot be found.
        """
        header_content = self.request.headers.get_first(name, default)
        if header_content is default_mark:
            raise KeyError(
                "The name {} cannot be found in headers.".format(name))
        return header_content

    def get_all_headers(self, name: str) -> List[str]:
        """
        Return all headers with the name by list.

        If the header cannot be found, it will return an empty list.
        """
        return self.request.headers.get_list(name, [])

    def set_header(self, name: str, value: str):
        """
        Set a response header with the name and value, this will override any
        former value(s) with the same name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot set a new header after the "
                                 "initial is written.")
        self._headers[name] = ensure_str(value)

    def add_header(self, name: str, value: str):
        """
        Add a response header with the name and value, this will not override
        any former value(s) with the same name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot add a new header after the "
                                 "initial is written.")
        self._headers.add(name, ensure_str(value))

    def clear_header(self, name: str):
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

    def get_cookie(self, name: str, default: Optional[str]=None) -> str:
        """
        Return first Cookie in the request header(s) with the name.

        If the cookie is expired or doesn't exist, it will return the default
        value.
        """
        cookie = self.request.cookies.get(name, None)
        if cookie is None:
            return default
        return cookie.value

    def set_cookie(self, name: str, value: str,
                   domain: Optional[str]=None,
                   expires: Optional[str]=None,
                   path: str="/", expires_days: Optional[int]=None,
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

    def clear_cookie(self, name: str):
        """
        Clear a cookie with the name.
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot clear a cookie after the "
                                 "initial is written.")
        self.set_cookie(name=name, value="", expires=format_timestamp(0))

    def clear_all_cookies(self):
        """
        Clear response cookie(s).
        """
        if self._initial_written:
            raise HTTPError(500, "You cannot clear cookies after the "
                                 "initial is written.")
        for cookie_name in self.request.cookies.keys():
            self.clear_cookie(cookie_name)

    def get_secure_cookie(self, name: str, max_age_days: int=31,
                          default=None) -> str:
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

    def set_secure_cookie(self, name: str, value: str,
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

        self.set_cookie(ensure_str(name), ensure_str(content),
                        expires_days=expires_days, **kwargs)

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
    def csrf_form_html(self) -> str:
        """
        Return a HTML form field contains _csrf value.
        """
        value = self._csrf_value
        return "<input type=\"hidden\" name=\"_csrf\" value=\"{}\">".format(
            value)

    def write(self, text: Union[str, bytes], clear_text: bool=False):
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
        self._response_body += ensure_bytes(text)

    @property
    def render_string(self) -> Callable[
        [str, Optional[Mapping[str, str]]],
            str]:
        warnings.warn("RequestHandler.render_string is deprecated, \
            use RequestHandler.render_str instead.")

        return self.render_str

    def get_template_args(self) -> Dict[str, Any]:
        return {
            "handler": self,
            "csrf_form_html": self.csrf_form_html
        }

    async def render_str(
        self, template_name: str,
            template_dict: Optional[Mapping[str, str]]=None) -> str:
        """
        Render Template in template folder into string.

        You can Specify Template Engine by override this function.
        """

        template_args = self.get_template_args()

        template_args.update(**template_dict)

        if "template_path" not in self.settings.keys():
            raise ValueError(
                "Cannot found template_path. "
                "Please provide template_path through Application Settings.")

        parsed_tpl = await self.app._tpl_loader.load_template(
            template_name)
        return await parsed_tpl.render_str(**template_args)

    async def render(
        self, template_name: str,
            template_dict: Optional[Mapping[str, str]]=None):
        """
        Render the template with render_str, and write them into response
        body directly.
        """
        self.finish(
            await self.render_str(
                template_name, template_dict=template_dict))

    def redirect(self, url: str, permanent: bool=False,
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
            status_message=protocol.status_code_text[status],
            url=url))

    def set_body_etag(self):
        """
        Set etag header of response_body.
        """
        if not hasattr(self, "__body_etag"):
            sha1_hash_object = hashlib.sha1()
            sha1_hash_object.update(self._response_body)

            self.__body_etag = '"{}"'.format(sha1_hash_object.hexdigest())
            if self.__body_etag is not '""':
                self.set_header("etag", self.__body_etag)

    @property
    def _body_etag(self) -> str:
        self.set_body_etag()
        return self.__body_etag

    def check_body_etag(self) -> bool:
        """
        Check etag header of response_body.
        """
        computed_etag = ensure_bytes(self._body_etag)
        etags = re.findall(
            br'\*|(?:W/)?"[^"]*"',
            ensure_bytes(self.get_header("if-none-match", ""))
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
            raise HTTPError(500, "Cannot write initial twice.")
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
            self.set_header("date", format_timestamp())

        self._headers.accept_cookies_for_response(self._cookies)

        if self.settings.get("csrf_protect", False):
            self.set_csrf_value()

        self.connection.write_initial(
            http_version=self.http_version,
            status_code=self._status_code, headers=self._headers)

        self._initial_written = True

    def flush(self):
        if self._finished:
            raise HTTPError(
                500, "Cannot Flush the request when it has already finished.")

        if not self._initial_written:
            self.write_initial()

        if not self._body_written:
            raise HTTPError(500, "Body is not written.")
        self.connection.write_body(self._response_body)
        self._response_body.clear()

    def finish(self, text: Optional[Union[str, bytes]]=None):
        """
        Finish the request, send the response. If a text is passed, it will be
        write first, after that, the request will be finished.

        If it is called more than one time, it will raise an error.
        """
        if self._finished:
            raise HTTPError(
                500, "Cannot Finish the request when it has already finished.")

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

    def write_error(self, error_code: int,
                    message: Optional[Union[str, bytes]]=None,
                    exc_info: Optional[tuple]=None):
        """
        Respond an error to client.

        You may override this page if you want to custom the error page.
        """
        self._status_code = error_code
        self.set_header("Content-Type", "text/html; charset=utf-8")

        if self._status_code >= 400:
            self.set_header("Connection", "Close")

        content = ""

        if message:
            content += html.escape(ensure_str(message)) + "\n\n"

        if self.settings.get("debug", False) and exc_info:
            print(self.request, file=sys.stderr)

            traceback.print_exception(*exc_info)

            content += html.escape(
                "\n".join(traceback.format_exception(*exc_info))) + "\n\n"

        self.write(
            _DEFAULT_ERROR_TPL.format(
                error_code=error_code,
                status_code_detail=protocol.status_code_text[error_code],
                content=content),
            clear_text=True)

        self.finish()

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

    async def get(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle GET request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def post(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle POST request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def delete(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle DELETE request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def patch(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle PATCH request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def put(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle PUT request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def options(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle OPTIONS request,
        or it will raise an HTTPError(405) -- Method Not Allowed.

        **This is a Coroutine.**
        """
        raise HTTPError(405)

    async def _handle_request(self):
        """
        Method to handle the request.

        It checks the if request method is supported and allowed, and handles
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
            body = await getattr(self, self.request.method.lower())(
                *self.path_args, **self.path_kwargs)
            if not self._body_written:
                self.write(body)
        except HTTPError as e:
            self.write_error(e.status_code, e.message, sys.exc_info())
        except Exception as e:
            self.write_error(500, None, sys.exc_info())
        if not self._finished:
            self.finish()

    def data_received(self):
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
    async def handle_static_file(self, file_uri_path: str, *args, **kwargs):
        """
        Get the file from the given file path. Override this function if you
        want to customize the way to get file.
        """
        if not self.static_path:
            self.static_path = self.settings.get("static_path", "static")
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
    :arg aes_security: Default: `True`.
      Use `security.AESContext` to secure the data
      (such as: cookies). Turn it to false to use
      `security.HMACSecurityObject`. This attribute will not work unless the
      `security_secret` attribute is set.
    :arg allow_keep_alive: Default: `True`.
      Allow Keep Alive or not. This attribute will be passed to
      `server.HTTPServer` as an attribute.
    :arg debug: Enable Debug Feature.
    :arg csrf_protect: Enable Cross Site Request Forgeries(CSRF) protection.
    :arg static_path: Add a default static file handler with the static path.
    :arg static_handler_path: Default: `r"/static/(?P<file>.*?)"`.
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

        self.handlers = routing.RoutingLocator(default_handler=NotFoundHandler)

        self._tpl_loader = None
        self._sec_context = None

        if "template_path" in self.settings.keys():
            self._tpl_loader = templating.TemplateLoader(
                self.settings["template_path"],
                cache_template=(not self.settings.get("debug", False)),
                loop=self._loop)

        if "security_secret" in self.settings.keys():
            if self.settings.get("aes_security", True):
                self._sec_context = security.AESContext(
                    self.settings["security_secret"])
            else:
                self._sec_context = security.HMACSecurityContext(
                    self.settings["security_secret"])

        if "static_path" in self.settings.keys():
            static_handler_path = self.settings.get("static_handler_path",
                                                    r"/static/(?P<file>.*?)")
            self.handlers.add(static_handler_path, StaticFileHandler)

    @property
    def template_loader(self) -> templating.TemplateLoader:
        """
        .. deprecated:: 0.3
            For direct access to `TemplateLoader`.
            Use `Application._tpl_loader` instead.
        """
        warnings.warn(
            "`Application.template_loader` is deprecated. \
                Use `Application._tpl_loader` instead.",
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
            "`Application.security_object` is deprecated. \
                Use `Application._sec_context` instead.",
            DeprecationWarning)

        return self._sec_context

    def make_server(self) -> asyncio.Protocol:
        """
        Make a asyncio compatible server.
        """
        return functools.partial(
            ApplicationHTTPServer, app=self, loop=self._loop,
            allow_keep_alive=self.settings.get("allow_keep_alive", True))

    def listen(self, port: int,
               address: str="127.0.0.1",
               context: Optional[
                Union[bool, ssl.SSLContext]]=None) -> CoroutineType:
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
        srv = asyncio.ensure_future(f, loop=self._loop)
        return srv

    def add_handler(
        self, path: str, *args, name: Optional[str]=None,
        handler: Optional[RequestHandler]=None, **kwargs) -> Optional[
            Callable[[RequestHandler], RequestHandler]]:
        """
        Add a handler to handler list.
        If you specific a handler in parameter, it will return nothing.

        On the other hand, if you use it as a decorator, you should not pass
        a handler to this function or it will cause unexcepted result.

        That is::

          @app.add_handler("/")
          class RootHandler(ReuqestHandler): pass

        or::

          class RootHandler(ReuqestHandler): pass
          app.add_handler("/", handler=RootHandler)
        """
        def decorator(handler):
            self.handlers.add(path, handler, *args, name=name, **kwargs)
            return handler

        if handler is not None:
            decorator(handler)

        else:
            return decorator
