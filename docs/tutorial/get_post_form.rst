Get Client-Side Information
---------------------------
We have talked Routing on the last chapter, but how to get information
from the client-side?

Get and post form are the most common ways for server
to get information from the server. For a get form, all arugments
go with the link, and for a post form,
all arguments will be the body of the request.

After FutureFinity receives a request, FutureFinity will parse the request,
at that time, the form will be parsed too.

All the arguments that come from the link can be get by using
``RequestHandler.get_link_arg`` classmethod. And the arugments that
come from the body can be get by using ``RequestHandler.get_body_arg`` classmethod.

Let's see the example below:

.. literalinclude:: ../../examples/get_post_form.py
   :language: python3
   :lines: 24-39

The example will try to get the username from the link first, if it fails,
then it will show you a form for you to fill and submit by post.
