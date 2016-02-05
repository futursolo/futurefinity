Security and Client-Side Data Storage
-------------------------------------
Cookie is an important way for servers to store data on client-side.
However, its content can be forged by malicious clients, and the content is
accessible by the client. Therefore, FutureFinity provides two types of cookies
-- the normal cookie and secure cookie.

Let's look at the example below:

.. literalinclude:: ../../examples/cookie.py
   :language: python3
   :lines: 17-

It will try to get the user information from the cookie first, if it fails,
redirect visitors to login page to submit a username. After that, redirect
the visitors back to the index and show the username.

As shown above, we use ``RequestHandler.get_cookie`` to get the value of
a cookie with the name, and we use ``RequestHandler.set_cookie`` to
set a new cookie.

For redirecting requests to one other URL, we use ``RequestHandler.redirect``
function. Although, in this example, we returned the value of ``self.redirect``,
actually, you don't have to, the value of this function will always be ``None``,
and the request will be finished once the ``self.redirect`` returns.

But, as mentioned before, the content of cookies is accessible by the client,
and it can be forged. If we want to protect the content, we need to switch to
secure cookies.

Before we continue, we need a security secret for encryption, you can generate
one on your own, or you can use ``futurefinity.security.get_random_str``
function to generate a new one.

**Cryptography Warning**: If ``random.SystemRandom`` is unavailable, this
function will fallback to fake random number generator, which has no promise on
cryptography security.

In order to protect the content inside the cookie, we also need to use
`cryptography <https://cryptography.readthedocs.org/en/latest/>`_
library from PyPI. Please use ``pip install cryptography`` to install it.

We have to change the example as below:

.. literalinclude:: ../../examples/secure_cookie.py
   :language: python3
   :lines: 24-46

A security secret is like a password for a server, please treat it like a
password. If the security secret is changed, all former secure cookies will
become invalid.

You can pass the security secret as a application setting, all application settings are passed
by keywords arguments when the instance of application class is created.

**Cross-Site Request Forgeries(CSRF) Protection**

CSRF is one of malicious exploit of a website for a website to run unauthorized
commands or even transactions for a online shopping website.

For more information, please visit: `CSRF on Wikipedia <https://en.wikipedia.org/wiki/Cross-site_request_forgery>`_

To prevent these attacks, FutureFinity has a built-in CSRF protection. To enable
the protection, simply set ``csrf_protect=True`` and ``security_secret``
in application settings.
