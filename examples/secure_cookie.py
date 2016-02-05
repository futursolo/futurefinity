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

import futurefinity.web

import asyncio

app = futurefinity.web.Application(security_secret="__PUT_YOUR_SECRET_HERE__")


@app.add_handler("/")
class MainHandler(futurefinity.web.RequestHandler):
    async def get(self, *args, **kwargs):
        username = self.get_secure_cookie("username", default=None)
        if not username:
            return self.redirect("/login")

        return "Hi, %s!" % username


@app.add_handler("/login")
class LoginHandler(futurefinity.web.RequestHandler):
    async def get(self, *args, **kwargs):
        return ("<form method=\"post\">"
                "<input type=\"text\" name=\"username\">"
                "<input type=\"submit\" value=\"submit\">"
                "</form>")

    async def post(self, *args, **kwargs):
        username = self.get_body_arg("username")
        self.set_secure_cookie("username", username)
        return self.redirect("/")

app.listen(23333)

try:
    asyncio.get_event_loop().run_forever()
except KeyboardInterrupt:
    pass
