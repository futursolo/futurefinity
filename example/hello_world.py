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
