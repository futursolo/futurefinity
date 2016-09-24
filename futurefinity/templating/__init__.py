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

"""
FutureFinity Template.

Examples:

layout.html::
    <html>
        <head>
            <title><%= await get_page_title()s %></title>
        </head>
        <body>
            <% include "header.htm" %>

            <r= await self.blocks.body() %>
        </body>
    </html>

Examples:

header.html::
    <header>
        <nav><%= await get_page_title() %></nav>
    </header>

main.html::
    <% inherit "layout.html" %>
    <main>
        <% try %>
            <% async for article in db.articles.find() %>
                <div>article.title</div>
                <div>article.content</div>
            <% end %>
        <% except Exception as e %>
            <div>Internal Server Error.</div>
            <%= e %>
        <% end %>
    </main>


"""
from .utils import *

from .loader import TemplateLoader
from .template import Template
