FutureFinity |release| Documentation
========================================

.. highlight:: python3

Overview
--------
  FutureFinity is an asynchronous web framework, using asyncio, inspired by Tornado and Flask.
  Benefit from the non-blocking model and asyncio, FutureFinity can handle thousands of requests
  at the same time.

Hello, World!
-------------

.. code-block:: python3

  import futurefinity.web
  import asyncio

  loop = asyncio.get_event_loop()
  app = futurefinity.web.Application()

  @app.add_handler("/")
  class RootHandler(futurefinity.web.RequestHandler):
      async def get(self, *args, **kwargs):
          return "Hello, World!"

  app.listen(23333)

  try:
      loop.run_forever()
  except KeyboardInterrupt:
      pass

Tutorial
--------
Based on the "Hello, World!" example, we can add more exciting features to it.

Dynamic Routing:

.. code-block:: python3

  @app.add_handler("/{name}")
  class DynamicRoutingHandler(futurefinity.web.RequestHandler):
      async def get(self, *args, **kwargs):
          return "Hello, " + kwargs["name"] + "!"

Custom HTTP Header:

.. code-block:: python3

  @app.add_handler("/custom-header")
  class CustomHeaderHandler(futurefinity.web.RequestHandler):
      async def get(self, *args, **kwargs):
          header = self.get_header("user-agent",
                                   default="The UA God Only Knows.")
          self.set_header("request-user-agent", header)
          self.add_header("request-user_cookie",
                          "Your US should be shown on the above.")
          return "If you saw nothing except this sentence, use curl -i."

User Cookie:

.. code-block:: python3

  @app.add_handler("/user_cookie")
  class UserCookieHandler(futurefinity.web.RequestHandler):
      async get(self, *args, **kwargs):
          round_num = int(self.get_cookie("rofl-round", default=450))
          self.set_cookie("rofl-round", str(round_num + 100))
          return "If you saw nothing except this sentence, use curl -i."

Link argument(s), Body argument(s), and UTF-8 support:

.. code-block:: python3

  @app.add_handler("/link_arg_body_arg_and_utf8")
  class LinkArgBodyArgAndUTF8Handler(futurefinity.web.RequestHandler):
      async def get(self, *args, **kwargs):
          blessing_words = ("汝%(husband_name)sは、この女%(wife_name)sを妻とし、<br>"
                            "良き時も悪き時も、富める時も貧しき時も、<br>"
                            "病める時も健やかなる時も、<br>"
                            "共に歩み、他の者に依らず、<br>"
                            "死が二人を分かつまで、愛を誓い、<br>"
                            "妻を想い、妻のみに添うことを、<br>"
                            "神聖なる婚姻の契約のもとに、<br>"
                            "誓いますか？<br>"
                            "<br>"
                            "汝%(wife_name)sは、この男%(husband_name)sを夫とし、<br>"
                            "良き時も悪き時も、富める時も貧しき時も、<br>"
                            "病める時も健やかなる時も、共に歩み、<br>"
                            "他の者に依らず、死が二人を分かつまで、<br>"
                            "愛を誓い、夫を想い、夫のみに添うことを、<br>"
                            "神聖なる婚姻の契約のもとに、誓いますか？") % {
                                "husband_name": self.get_link_arg("husband_name"),
                                "wife_name": self.get_link_arg("wife_name")
                           }

          return blessing_words

      async def post(self, *args, **kwargs):
          husband_response = self.get_body_arg("husband_response")
          wife_response = self.get_body_arg("wife_response")
          if not (husband_response == "はい、誓います。" and
             wife_response == "はい、誓います。"):
              return "なんでやねん!"

              ending_words = ("皆さん、お二人の上に神の祝福を願い、<br>"
                              "結婚の絆によって結ばれた このお二人を<br>"
                              "神が慈しみ深く守り、助けてくださるよう<br>"
                              "祈りましょう。<br>"
                              "<br>"
                              "宇宙万物の造り主である父よ、<br>"
                              "あなたはご自分にかたどって人を造り、<br>"
                              "夫婦の愛を祝福してくださいました。<br>"
                              "今日結婚の誓いをかわした二人の上に、<br>"
                              "満ちあふれる祝福を注いでください。<br>"
                              "二人が愛に生き、健全な家庭を造りますように。<br>"
                              "喜びにつけ悲しみにつけ信頼と感謝を忘れず、<br>"
                              "二人で支えられて仕事に励み、<br>"
                              "困難にあっては慰めを見いだすことができますように。<br>"
                              "また多くの友に恵まれ、結婚がもたらす<br>"
                              "恵みによって成長し、実り豊かな生活を<br>"
                              "送ることができますように。")

          return ending_words

Also see:
---------
.. toctree::
   :titlesonly:

   install
   web
   server
   utils


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
