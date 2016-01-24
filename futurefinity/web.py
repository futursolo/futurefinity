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


from futurefinity.utils import ensure_str, ensure_bytes, format_timestamp
from futurefinity.protocol import (status_code_text, HTTPHeaders, HTTPCookies,
                                   HTTPResponse, HTTPError)

import futurefinity
import futurefinity.server
import futurefinity.interface

import asyncio

import os
import re
import sys
import html
import time
import uuid
import types
import routes
import typing
import hashlib
import mimetypes
import traceback


__all__ = ["ensure_bytes", "ensure_str", "render_template", "WebError"]


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

    def __init__(self, *args, **kwargs):
        self.app = kwargs.get("app")
        self.server = kwargs.get("server")
        self.request = kwargs.get("request")
        self.response = kwargs.get("response", HTTPResponse())
        self.respond_request = kwargs.get("respond_request")

        self.path = self.request.path

        self._session = None

        self._response_cookies = HTTPCookies()

        self._csrf_value = None

        self._written = False
        self._finished = False

    def get_link_arg(self, name: str, default: str=None) -> str:
        """
        Return first argument in the link with the name.
        """
        return self.request.queries.get_first(name, default)

    def get_body_arg(self, name: str, default: str=None) -> str:
        """
        Return first argument in the body with the name.
        """
        return self.request.body.get_first(name, default)

    def get_header(self, name: str, default: str=None) -> str:
        """
        Return First Header with the name.
        """
        return self.request.headers.get_first(name, default)

    def get_all_headers(self, name: str, default: str=None) -> list:
        """
        Return All Header with the name by list.
        """
        return self.request.headers.get_list(name, [default])

    def set_header(self, name: str, value: str):
        """
        Set a response header with the name and value, this will override any
        former value(s) with the same name.
        """
        self.response.headers[name] = ensure_str(value)

    def add_header(self, name: str, value: str):
        """
        Add a response header with the name and value, this will not override
        any former value(s) with the same name.
        """
        self.response.headers.add(name, ensure_str(value))

    def clear_header(self, name: str):
        """
        Clear response header(s) with the name.
        """
        if name in self.response.headers.keys():
            del self.response.headers[name]

    def clear_all_headers(self):
        """
        Clear all response header(s).
        """
        self.response.headers = HTTPHeaders()

    def get_cookie(self, name: str, default: str=None) -> str:
        """
        Return first Cookie in the request header(s) with the name.
        """
        cookie = self.request.cookies.get(name, None)
        if cookie is None:
            return default
        return cookie.value

    def set_cookie(self, name: str, value: str, domain: str=None,
                   expires: str=None, path: str="/", expires_days: int=None,
                   secure: bool=False, httponly: bool=False):
        """
        Set a cookie with attribute(s).
        """
        self.response.cookies[name] = value
        if domain:
            self.response.cookies[name]["domain"] = domain
        if expires:
            self.response.cookies[name]["expires"] = expires
        self.response.cookies[name]["path"] = path
        self.response.cookies[name]["max-age"] = expires_days
        self.response.cookies[name]["secure"] = secure
        self.response.cookies[name]["httponly"] = httponly

    def clear_cookie(self, name: str):
        """
        Clear a cookie with the name.
        """
        self.set_cookie(name=name, value="",
                        expires=format_timestamp(0))

    def clear_all_cookies(self):
        """
        Clear response cookie(s).
        """
        for cookie_name in self.request.cookies.keys():
            self.clear_cookie(cookie_name)

    def get_secure_cookie(self, name: str, max_age_days: int=31) -> str:
        """
        Get a secure cookie with the name, if it validates, or None.

        The implementation depends on the interface you use.
        """
        valid_length = None
        if max_age_days:
            valid_length = max_age_days * 86400

        cookie_content = self.get_cookie(name)

        if cookie_content is None:
            return None

        return self.app.interfaces.get(
            "secure_cookie").lookup_origin_text(cookie_content, valid_length)

    def set_secure_cookie(self, name: str, value: str,
                          expires_days: int=30, **kwargs):
        """
        Set a secure cookie.

        The implementation depends on the interface you use.

        You must set a security_secret in Application Settings before

        you use this method. It can be generated by::

          futurefinity.utils.security_secret_generator(length=16)

        Once security_secret is generated, treat it as a password,
        change security_secret will cause all secure_cookie become invalid.
        """
        content = self.app.interfaces.get(
            "secure_cookie").generate_secure_text(value)

        self.set_cookie(ensure_str(name), ensure_str(content),
                        expires_days=expires_days, **kwargs)

    async def get_session(self, name: str, default: str=None) -> str:
        """
        Get a session value in with if it exists or return the default.

        The implementation depends on the interface you use.
        """
        if self._session is None:
            self._session = await self.app.interfaces.get(
                "session").get_session(self)
        return self._session.get(name, default)

    async def set_session(self, name: str, value: str):

        """
        Set a session value with the name. If the name exists,
        it will override the value.

        The implementation depends on the interface you use.
        """
        if self._session is None:
            self._session = await self.app.interfaces.get(
                "session").get_session(self)
        self._session[name] = value

    def check_csrf_value(self):
        """
        Validate if csrf value is valid.

        FutureFinity uses a secure cookie _csrf and a body argument _csrf
        to prevent CSRF attack.
        """
        cookie_value = self.get_secure_cookie("_csrf")
        form_value = self.get_body_arg("_csrf")

        if not (cookie_value and form_value):
            raise HTTPError(403)  # CSRF Value is not set.

        if cookie_value != form_value:
            raise HTTPError(403)  # CSRF Value does not match.

    def set_csrf_value(self):
        """
        Generate CSRF value and set it to secure cookie.
        """
        if self._csrf_value is not None:
            return
        self._csrf_value = str(uuid.uuid4())
        self.set_secure_cookie("_csrf", self._csrf_value, expires_days=1)

    def get_csrf_value(self):
        """
        Return a valid CSRF value to this request.

        If csrf value does not exist, generate and set it.
        """
        self.set_csrf_value()
        return self._csrf_value

    def csrf_form_html(self) -> str:
        """
        Return a HTML form field contains _csrf value.
        """
        value = self.get_csrf_value()
        return "<input type=\"hidden\" name=\"_csrf\" value=\"%s\">" % value

    def write(self, text: typing.Union[str, bytes], clear_text: bool=False):
        """
        Store response body.

        If write() is called for many times, it will connect all text together.
        """
        if self._finished:
            return
        self._written = True
        self.response.body += ensure_bytes(text)
        if clear_text:
            self.response.body = ensure_bytes(text)

    def render_string(self, template_name: str, template_dict: dict) -> str:
        """
        Render Template in template folder into string.

        Currently, FutureFinity uses Jinja2 as the Default Template Rendering
        Engine. However, You can Specify Template Engine by Customizing
        Template Interface.
        """

        template_args = {
            "handler": self,
            "csrf_form_html": self.csrf_form_html
        }

        renderer = self.app.interfaces.get("template")
        return renderer.render_template(template_name, template_dict)

    def render(self, template_name: str, template_dict=None):
        """
        Render the template with render_string, and write them into response
        body directly.
        """
        self.write(self.render_string(template_name,
                                      template_dict=template_dict))

    def redirect(self, url: str, permanent: bool=False, status: int=None):
        """
        Rediect request to other location.
        """
        if self._finished:
            raise Exception("Cannot redirect after request finished.")
        if status is None:
            status = 301 if permanent else 302
        else:
            assert isinstance(status, int) and 300 <= status <= 399
        self.response.status_code = status
        self.set_header("location", ensure_str(url))
        self.write("<!DOCTYPE HTML>"
                   "<html>"
                   "<head>"
                   "    <meta charset=\"utf-8\">"
                   "    <title>%(status_code)d %(status_message)s</title>"
                   "</head>"
                   "<body>"
                   "    <h1>%(status_code)d %(status_message)s</h1>"
                   "    The document has moved <a href=\"%(url)s\">here</a>."
                   "</body>"
                   "</html>" % {
                       "status_code": status,
                       "status_message": status_code_text[status],
                       "url": ensure_str(url)
                    })
        self.finish()

    def compute_etag(self):
        """
        Compute etag header of response_body.
        """
        hasher = hashlib.sha1()
        hasher.update(self.response.body)
        return '"%s"' % hasher.hexdigest()

    def check_etag_header(self):
        """
        Check etag header of response_body.
        """
        computed_etag = ensure_bytes(self.response.headers.get_first("etag"))
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

    def set_etag_header(self):
        """
        Set response etag header.
        """
        etag = self.compute_etag()
        if etag is not None:
            self.set_header("etag", etag)

    def finish(self):
        """
        Finish the request, send the response.
        """
        if self._finished:
            return
        self._finished = True

        if self.app.settings.get("csrf_protect", False):
            self.set_csrf_value()

        if ("etag" not in self.response.headers and
           self.response.status_code == 200):
            self.set_etag_header()

        if self.check_etag_header():
            self.response.status_code = 304
            self.response.body = b""
            for header_name in ["allow", "content-encoding",
                                "content-language", "content-length",
                                "content-md5", "content-range", "content-type",
                                "last-modified"]:
                self.clear_header(header_name)

        self.respond_request(self.request, self.response)

    def write_error(self, error_code: int,
                    message: typing.Union[str, bytes]=None,
                    exc_info: tuple=None):
        """
        Respond an error to client.
        """
        self.response.status_code = error_code
        self.set_header("Content-Type", "text/html")
        self.write("<!DOCTYPE HTML>"
                   "<html>"
                   "<head>"
                   "    <meta charset=\"UTF-8\">"
                   "    <title>%(error_code)d: %(status_code_detail)s</title>"
                   "</head>"
                   "<body>"
                   "    <div>%(error_code)d: %(status_code_detail)s</div>" % {
                        "error_code": error_code,
                        "status_code_detail": status_code_text[error_code]
                   },
                   clear_text=True)
        if message:
            self.write(""
                       "    <div>%(message)s</div>" % {
                           "message": ensure_str(message)})

        if self.app.settings.get("debug", False) and exc_info:
            print(self.request, file=sys.stderr)

            traceback.print_exception(*exc_info)
            for line in traceback.format_exception(*exc_info):
                self.write(
                    "    <div>%s</div>" % html.escape(line).replace(" ",
                                                                    "&nbsp;"))

        self.write(""
                   "</body>"
                   "</html>")

    async def head(self, *args, **kwargs):
        """
        Respond the Head Request.
        """
        get_return_text = await self.get(*args, **kwargs)
        if self.response.status_code != 200:
            return
        if self._written is True:
            self.set_header("content-length", str(len(self.response.body)))
        else:
            self.set_header("content-length", str(len(get_return_text)))
        self.write(b"", clear_text=True)

    async def get(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle GET request,
        or it will raise an HTTPError(405) -- Method Not Allowed.
        """
        raise HTTPError(405)

    async def post(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle POST request,
        or it will raise an HTTPError(405) -- Method Not Allowed.
        """
        raise HTTPError(405)

    async def delete(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle DELETE request,
        or it will raise an HTTPError(405) -- Method Not Allowed.
        """
        raise HTTPError(405)

    async def patch(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle PATCH request,
        or it will raise an HTTPError(405) -- Method Not Allowed.
        """
        raise HTTPError(405)

    async def put(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle PUT request,
        or it will raise an HTTPError(405) -- Method Not Allowed.
        """
        raise HTTPError(405)

    async def options(self, *args, **kwargs):
        """
        Must be overridden in subclass if you want to handle OPTIONS request,
        or it will raise an HTTPError(405) -- Method Not Allowed.
        """
        raise HTTPError(405)

    async def handle(self, *args, **kwargs):
        """
        Method to handle the request.

        It checks the if request method is supported and allowed, and handles
        them to right class function, gets the return value, writes them to
        response body, and finishes the request.
        """
        try:
            if self.request.method not in self.allow_methods:
                raise HTTPError(405)
            if self.app.settings.get(
             "csrf_protect", False
             ) and self.request.body_expected is True:
                self.check_csrf_value()
            body = await getattr(self,
                                 self.request.method.lower())(*args, **kwargs)
            if not self._written:
                self.write(body)
            await self.app.interfaces.get(
                "session").write_session(self, self._session)
        except HTTPError as e:
            self.write_error(e.status_code, e.message, sys.exc_info())
        except Exception as e:
            self.write_error(500, None, sys.exc_info())
        self.finish()


class NotFoundHandler(RequestHandler):
    """
    Default RequestHandler when link matches no handler.

    By default, it just returns a 404 Error to the client.
    """
    async def handle(self, *args, **kwargs):
        self.write_error(404)
        self.finish()


class StaticFileHandler(RequestHandler):
    """
    Handler that handles static files.

    Warning: You should use Web Server(such as: Nginx) to handle Static Files.
             StaticFileHandler should only be used in development.
    """

    async def handle_static_file(self, file_uri_path: str, *args, **kwargs):
        file_path = os.path.join(
            self.app.settings.get("static_path", "static"), file_uri_path)

        if not os.path.realpath(file_path).startswith(
         os.path.realpath(self.app.settings.get("static_path", "static"))):
            raise HTTPError(403)
        if not os.path.exists(file_path):
            raise HTTPError(404)
        if os.path.isdir(file_path):
            raise HTTPError(403)

        file_size = os.path.getsize(file_path)
        if file_size >= 1024 * 1024 * 50:
            # StaticFileHandler Currently does not file bigger than 50MB.
            raise HTTPError(500, "Static File Size Too Large.")

        mime = mimetypes.guess_type(file_uri_path)[0]
        mime = mime or "application/octet-stream"
        self.set_header("content-type", mime)

        with open(file_path, "rb") as f:
            self.write(f.read())
        self.finish()

    async def get(self, *args, **kwargs):
        await self.handle_static_file(file_uri_path=kwargs["file"])


class Application:
    """
    Class that its instance creates asyncio compatible servers,
    stores handler list, finds every request's handler,
    and passes it to server.
    """
    def __init__(self, **kwargs):
        self._loop = kwargs.get("loop", asyncio.get_event_loop())
        self.handlers = routes.Mapper()
        self.settings = kwargs
        self.interfaces = futurefinity.interface.InterfaceFactory(app=self)

    def make_server(self) -> asyncio.Protocol:
        """
        Make a asyncio compatible server.
        """
        self.interfaces.initialize()
        return (lambda: futurefinity.server.HTTPServer(app=self,
                                                       loop=self._loop))

    def listen(self, port: int,
               address: str="127.0.0.1") -> types.CoroutineType:
        """
        Make the server to listen to the specified port and address.
        """
        f = self._loop.create_server(self.make_server(), address, port)
        srv = self._loop.run_until_complete(f)
        return srv

    def add_handler(self, route_str: str, name: str=None,
                    handler: RequestHandler=None):
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
        def decorator(cls):
            self.handlers.connect(name, route_str, __handler__=cls)
            return cls
        if handler is not None:
            decorator(handler)
        else:
            return decorator

    def find_handler(self, path: str) -> RequestHandler:
        """
        Find a handler that matches the path.

        If a handler that matches the path cannot be found, it will return
        NotFoundHandler, which returns 404 Not Found to client.
        """
        matched_obj = self.handlers.match(path)
        if not matched_obj:
            matched_obj = {"__handler__": NotFoundHandler}
        return matched_obj
