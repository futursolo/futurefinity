from futurefinity.utils import *

import urllib.parse
import asyncio
import ssl
import re
import http.cookies
import http.client

_MAX_HEADER_LENGTH = 4096

_MAX_BODY_LENGTH = 52428800  # 50M

_CRLF_MARK = "\r\n"
_CRLF_BYTES_MARK = b"\r\n"

_LF_MARK = "\n"
_LF_BYTES_MARK = b"\n"


_multipart_boundary_handlers = {}


class HTTPServer(asyncio.Protocol):
    def __init__(self, app, enable_h2=False):
        self.app = app
        self.enable_h2 = enable_h2
        self.reset_server()

    def reset_server(self):
        self.data = b""
        self.crlf_mark = True
        self.http_version = 10
        self._header_parsed = False
        self._body_parsed = False
        self._multipart_master = False
        self._multipart_boundary = None
        self._multipart_slave = False
        self.parsed_headers = None
        self.request_cookies = None
        self.parsed_path = None
        self.parsed_queries = None
        self.parsed_body = None
        self.transport = None

    def split_data(self, data, mark_repeat=1, max_part=0):
        spliter = _CRLF_BYTES_MARK
        if isinstance(data, bytes):
            if not self.crlf_mark:
                spliter = _LF_BYTES_MARK
        elif isinstance(data, str):
            if not self.crlf_mark:
                spliter = _LF_MARK
            else:
                spliter = _CRLF_MARK
        else:
            raise ValueError("%s type is not Splittable." % (type(data)))

        spliter = spliter * mark_repeat

        return data.split(spliter, max_part - 1)

    def decide_mark(self):
        crlf_position = self.data.find(b"\r\n\r\n")
        lf_position = self.data.find(b"\n\n")
        if crlf_position == -1 and lf_position == -1 and len(
           self.data) < _MAX_HEADER_LENGTH:
            return -1  # Request Not Completed, Wait.
        elif crlf_position != -1 and lf_position != -1:
            if lf_position > crlf_position:
                self.crlf_mark = True
            else:
                self.crlf_mark = False
        elif crlf_position != -1:
            self.crlf_mark = True
        elif lf_position != -1:
            self.crlf_mark = False
        else:
            return 1  # 413 Request Entity Too Large

    def parse_http_v1_header_and_cookies(self):
        parsed_headers = HTTPHeaders()

        raw_header, raw_body = self.split_data(self.data, mark_repeat=2,
                                               max_part=2)
        self.data = raw_body

        raw_header = raw_header.decode()

        basic_info, headers = self.split_data(raw_header, max_part=2)

        basic_info = basic_info.split(" ")

        if len(basic_info) != 3:
            return 1  # 400 Bad Request

        method, path, http_version = basic_info

        if http_version.lower() == "http/1.1":
            self.http_version = 11

        for header in self.split_data(headers):
            (key, value) = header.split(":", 1)
            parsed_headers.add(key.strip(), value.strip())

        parsed_headers[":path"] = path
        parsed_headers[":method"] = method
        if "host" in parsed_headers.keys():
            parsed_headers[":authority"] = parsed_headers.pop("host")
        self.parsed_headers = parsed_headers

        self.request_cookies = http.cookies.SimpleCookie(
            self.parsed_headers.get("cookie"))
        self._header_parsed = True

    def parse_path_and_query(self):
        parsed_queries = {}
        parsed_path = urllib.parse.urlparse(self.parsed_headers.get(":path"))

        for query in urllib.parse.parse_qsl(parsed_path.query):
            if query[0] not in parsed_queries.keys():
                parsed_queries[query[0]] = []
            parsed_queries[query[0]].append(query[1])
        self.parsed_path = parsed_path
        self.parsed_queries = parsed_queries

    def parse_body(self, data=None):
        content_type = self.parsed_headers.get("content-type")
        content_length = int(self.parsed_headers.get("content-length"))
        if content_type.startswith("application/x-www-form-urlencoded"):
            if len(self.data) < content_length:
                return -1  # Request Not Completed, Wait.
            body = urllib.parse.parse_qsl(self.data[:content_length].decode(),
                                          keep_blank_values=True)
            parsed_body = {}
            for (key, value) in body:
                if key not in parsed_body.keys():
                    parsed_body[key] = []
                parsed_body[key].append(value)
        elif content_type.startswith("multipart/form-data"):
            self._multipart_master = True
            if not self._multipart_boundary:
                for field in content_type.split(";"):
                    if field.strip()[:8] == "boundary":
                        boundary = field.split("=")[1].strip().encode()
                        _multipart_boundary_handlers[
                            boundary] = self.parse_body
            if len(self.data) < content_length:
                return -1  # Request Not Completed, Wait.

            del _multipart_boundary_handlers[boundary]

            body = self.data
            if body.startswith(b'"') and body.endswith(b'"'):
                data = data[1:-1]
            final_boundary_index = data.rfind(
                b"--" + self._multipart_boundary + b"--")
            if final_boundary_index == -1:
                return 1
            for field in data[:final_boundary_index].split(
             b"--" + self._multipart_boundary + b"\r\n"):
                if not part:
                    continue
                field_header, field_content = self.split_data(field,
                                                              mark_repeat=2,
                                                              max_part=2)
            print(self.data)
        self.parsed_body = parsed_body
        """
eoh = part.find(b"\r\n\r\n")
if eoh == -1:
    gen_log.warning("multipart/form-data missing headers")
    continue
headers = HTTPHeaders.parse(part[:eoh].decode("utf-8"))
disp_header = headers.get("Content-Disposition", "")
disposition, disp_params = _parse_header(disp_header)
if disposition != "form-data" or not part.endswith(b"\r\n"):
    gen_log.warning("Invalid multipart/form-data")
    continue
value = part[eoh + 4:-2]
if not disp_params.get("name"):
    gen_log.warning("multipart/form-data value missing name")
    continue
name = disp_params["name"]
if disp_params.get("filename"):
    ctype = headers.get("Content-Type", "application/unknown")
    files.setdefault(name, []).append(HTTPFile(
        filename=disp_params["filename"], body=value,
        content_type=ctype))
else:
    arguments.setdefault(name, []).append(value)

        """

    def connection_made(self, transport):
        self.transport = transport
        context = self.transport.get_extra_info("sslcontext", None)
        if context and ssl.HAS_ALPN:  # NPN will not be supported
            alpn_protocol = context.selected_alpn_protocol()
            if alpn_protocol in ["h2", "h2-14", "h2-15", "h2-16", "h2-17"]:
                self.http_version = 20
            else:
                raise Exception("Unsupported Protocol")

    def data_received(self, data):
        print("Data Received: ")
        print(data)
        if self.http_version == 20:
            return  # HTTP/2 will be implemented later.

        else:
            self.data_received_http_v1(data)

    def data_received_http_v1(self, data):
        self.data += data

        connection_status = self.decide_mark()
        if connection_status == -1:
            return  # Request Not Completed, Wait.
        if connection_status == 1:
            pass  # 413 Request Entity Too Large.

            # 400 and 413 will be implemented later.

        if not self._header_parsed:
            self.parse_http_v1_header_and_cookies()
            self.parse_path_and_query()

        if self.parsed_headers[":method"] in body_expected_method:
            if self.parse_body() == -1:
                return  # Request Not Completed, Wait.

        asyncio.ensure_future(self.app.process_handler(
            make_response=self.make_response,
            http_version=self.http_version,
            method=self.parsed_headers.get(":method"),
            path=self.parsed_path.path,
            queries=self.parsed_queries,
            request_body=self.parsed_body,
            request_headers=self.parsed_headers,
            request_cookies=self.request_cookies
        ))

    def make_response(self, status_code,
                      response_headers, response_body):
        if self.http_version == 20:
            return  # HTTP/2 will be implemented later.
        else:
            self.make_http_v1_response(status_code,
                                       response_headers, response_body)

    def make_http_v1_response(self, status_code,
                              response_headers, response_body):
        response_text = b""
        if self.http_version == 10:
            response_text += b"HTTP/1.0 "
        elif self.http_version == 11:
            response_text += b"HTTP/1.1 "

        response_text += (str(status_code)).encode() + b" "

        response_text += http.client.responses[status_code].encode() + b"\r\n"
        for (key, value) in response_headers.get_all():
            response_text += ("%(key)s: %(value)s\r\n" % {
                "key": key, "value": value}).encode()
        response_text += b"\r\n"
        response_text += ensure_bytes(response_body)
        self.transport.write(response_text)
        self.transport.close()
