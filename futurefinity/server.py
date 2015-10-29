from futurefinity.utils import *

from urllib.parse
import asyncio
import ssl
import re
import http.cookies

_MAX_HEADER_LENGTH = 4096
_CRLF_MARK = "\r\n"
_CRLF_BYTES_MARK = b"\r\n"

_LF_MARK = "\n"
_LF_BYTES_MARK = b"\n"

_CRLF_HEADER_RE = re.complie(r"(.*):(.*)\r\n")
_LF_HEADER_RE = re.complie(r"(.*):(.*)\n")


class EchoServerClientProtocol(asyncio.Protocol):
    def __init__(self, app, enable_h2=False):
        self.app = app
        self.enable_h2 = enable_h2
        self.data = b""
        self.crlf_mark = True
        self.http_version = 10

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

        basic_info, header = self.split_data(raw_header, max_part=2)

        basic_info = basic_info.split(" ")

        if len(basic_info) != 3:
            return 1  # 400 Bad Request

        method, path, http_version = basic_info

        if http_version.lower() = "http/1.1":
            self.http_version = 11

        header_re = _CRLF_HEADER_RE
        if not self.crlf_mark:
            header_re = _LF_HEADER_RE
        for (key, value) in re.findall(header, header_re):
            parsed_headers.add(key, value)

        parsed_headers[":path"] = path
        parsed_headers[":method"] = method
        if "host" in parsed_headers.keys():
            parsed_headers[":authority"] = parsed_headers.pop("host")
        self.parsed_headers = parsed_headers

        self.request_cookies = http.cookies.SimpleCookie(
            self.parsed_headers.get("cookie"))

    def parse_path_and_query(self):
        parsed_queries = {}
        parsed_path = urllib.parse.urlparse(self.parsed_headers.get(":path"))

        parsed_queries = parse_query(parsed_path.query)
        for query in urllib.parse.parse_qsl(queries):
            if query[0] not in parsed_queries.keys():
                parsed_queries[query[0]] = []
            parsed_queries[query[0]].append(query[1])
        self.parsed_path = parsed_path
        self.parsed_queries = parsed_queries

    def parse_body(self, body):
        parsed_body = {}
        print(body)
        for (key, value) in body:
            if key not in parsed_body.keys():
                parsed_body[key] = []
            parsed_body[key].append(value)
        return parsed_body

    def connection_made(self, transport):
        context = self.get_extra_info("sslcontext", None)
        if context and ssl.HAS_ALPN:  # NPN will not be supported
            alpn_protocol = context.selected_alpn_protocol()
            if alpn_protocol in ["h2", "h2-14", "h2-15", "h2-16", "h2-17"]:
                self.http_version = 20
            else:
                raise Exception("Unsupported Protocol")
        self.transport = transport

    def data_received(self, data):
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

        asyncio.ensure_future(self.app.process_handler(
            make_response=self.make_response,
            http_version=self.http_version,
            method=self.parsed_headers.get(":method"),
            path=self.parsed_path.path,
            queries=self.parsed_queries,
            request_body=None,
            request_headers=self.parsed_headers,
            request_cookies=self.request_cookies
        ))

    def make_response(self, status_code, http_version,
                      response_headers, response_body):
        for (key, value) in response_headers.items():
            for content in value:
                response.add_header(key, content)
        response.send_headers()
        response.write(ensure_bytes(response_body))
        await response.write_eof()
