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

from futurefinity.utils import render_template, HTTPError
import futurefinity.web
import asyncio
import hashlib


app = futurefinity.web.Application(
    template_path="example/template",
    debug=True
)


@app.add_handler("/")
class RootHandler(futurefinity.web.RequestHandler):
    @render_template("example.htm")
    async def get(self, *args, **kwargs):
        return {"greeting": None}

    @render_template("example.htm")
    async def post(self, *args, **kwargs):
        name = self.get_body_query("name")
        file = self.get_body_query("file1[]")
        md5_hash = hashlib.md5()
        md5_hash.update(file)
        print(md5_hash.hexdigest())
        return {"greeting": name}

if __name__ == '__main__':
    app.listen(8080)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
