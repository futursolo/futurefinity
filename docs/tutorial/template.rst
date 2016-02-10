Template Rendering
------------------
Template rendering of FutureFinity uses the Jinja2 Template Engine, but FutureFinity
replaces the ``TemplateLoader`` to load template from filesystem asynchronously
(it takes the advantage of multithreading).

Let's look at the example below:

.. literalinclude:: ../../examples/template_rendering.py
   :language: python3
   :lines: 17-

The example presents that FutureFinity supports two ways to render template.
One is ``RequestHandler.render`` classmethod, and the other one is
``futurefinity.template.render_template`` decorator.

For the information about the Jinja2 Template, please visit: `Jinja2 Documentation <http://jinja.pocoo.org/>`_

If you want to override the template engine, you can just override
``ReuqestHandler.render_string`` method to switch to other template engine.
