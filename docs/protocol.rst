``futurefinity.protocol`` -- HTTP Protocol Implementation
=========================================================

.. highlight:: python3

.. automodule:: futurefinity.protocol

.. autoclass:: futurefinity.protocol.HTTPError

.. autoclass:: futurefinity.protocol.CapitalizedHTTPv1Header

.. autoclass:: futurefinity.protocol.HTTPHeaders

.. automethod:: futurefinity.protocol.HTTPHeaders.copy

.. automethod:: futurefinity.protocol.HTTPHeaders.parse_http_v1_header

.. automethod:: futurefinity.protocol.HTTPHeaders.accept_cookies_for_request

.. automethod:: futurefinity.protocol.HTTPHeaders.accept_cookies_for_response

.. automethod:: futurefinity.protocol.HTTPHeaders.make_http_v1_header

.. autoclass:: futurefinity.protocol.HTTPFile

.. automethod:: futurefinity.protocol.HTTPFile.make_http_v1_form_field

.. autoclass:: futurefinity.protocol.HTTPBody

.. automethod:: futurefinity.protocol.HTTPBody.set_content_length

.. automethod:: futurefinity.protocol.HTTPBody.get_content_length

.. automethod:: futurefinity.protocol.HTTPBody.set_content_type

.. automethod:: futurefinity.protocol.HTTPBody.get_content_type

.. automethod:: futurefinity.protocol.HTTPBody.copy

.. automethod:: futurefinity.protocol.HTTPBody.parse_http_v1_body

.. automethod:: futurefinity.protocol.HTTPBody.make_http_v1_body

.. autoclass:: futurefinity.protocol.HTTPRequest

.. automethod:: futurefinity.protocol.HTTPRequest.parse_http_v1_request

.. automethod:: futurefinity.protocol.HTTPRequest.make_http_v1_request

.. autoclass:: futurefinity.protocol.HTTPResponse

.. automethod:: futurefinity.protocol.HTTPResponse.parse_http_v1_response

.. automethod:: futurefinity.protocol.HTTPResponse.make_http_v1_response
