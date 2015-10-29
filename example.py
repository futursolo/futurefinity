#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import futurefinity
import asyncio

app = futurefinity.Application(
    template_path="example/template",
    debug=True
)


@app.add_handler("/")
class RootHandler(futurefinity.RequestHandler):
    @futurefinity.render_template("example.htm")
    async def get(self, *args, **kwargs):
        return {"greeting": None}

    @futurefinity.render_template("example.htm")
    async def post(self, *args, **kwargs):
        name = self.get_body_query("name")
        return {"greeting": name}

if __name__ == '__main__':
    app.listen(8080)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
