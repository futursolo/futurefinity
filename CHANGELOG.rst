dev
---
- Fixed a Typo Bug in RequestHandler
- Fixed a Body Parsing Bug when content-type is `application/json`
- Fixed a Set Cookie Expires Days Bug
- Implemented HTTP 451(Unavailable For Legal Reasons)
- Print Exceptions in Protocol in debug mode
- Introduce FutureFinity Template
- Removed Jinja2 from Full Requirements
- Deprecated HAMCSecurityContext
- Deprecated AESGCMSecurityContext by AESContext
- Deprecation Tools
- Introduce FutureFinity Logging Facility
- Introduce New Routing Dispatcher.

v0.2.1
------
- Abstract HTTPv1 Protocol by HTTPv1Connection
- Initialize HTTPIncomingRequest and HTTPIncomingResponse
- Fixed Cookie Default Value Bug
- Introduce Streamed RequestHandler
- Removed Interface
- Introduce Security Module
- Introduce TemplateLoader
- Introduce HTTPClient
- Support Chunked Request and Chunked Response
- Introduce Standardized Error Handling

v0.1.1
------
- Introduce Secure Cookie interface
- Removed SecureCookieSession
- Fixed Content-Type Error when HTTPError Occurs
- Fixed CSRF Cookie errors
- Fixed Documentation Typo
- Added CSRF Unittest
- Added Keep-Alive Unittest
- Added Redirect Unittest

v0.1.0
------
- StaticFileHandler
- New Secure Cookies(Signed and AES GCM Encrypted)
- Introduce Interface
- Using Template Interface instead of Overriding Function
- Introduce Session Interface
- Introduce Secure Cookie Based Session
- Introduce Redis Based Session
- Etag Support

0.0.1
------
- Project Initialization
- Support GET Method
- Routing
- Jinja2 Template Rendering
- HTTP headers
- Cookies
- GET Queries
- POST URLEncoded Form
- POST Multipart Form
- Secure Cookies
- Security Secret Generator
- CSRF Protection
- Debug
- Error Handling
- Basic Documentation
