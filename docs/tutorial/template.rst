Template Rendering
------------------
FutureFinity uses its own Template Engine.

It enables the `async/await` statements in the template.

The ``TemplateLoader`` can load template from the filesystem asynchronously
(it takes the advantage of multithreading).

Let's look at the example below:

.. literalinclude:: ../../examples/template_rendering.py
   :language: python3
   :lines: 17-

The example presents that FutureFinity supports two ways to render template.
One is ``RequestHandler.render`` classmethod, and the other one is
``futurefinity.template.render_template`` decorator.

If you want to use your favourite template engine, you can just override
``ReuqestHandler.render_str`` method to switch to other template engines.
