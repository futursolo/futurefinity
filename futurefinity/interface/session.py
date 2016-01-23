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

from futurefinity.utils import *
import json
import uuid
import traceback
try:
    import aioredis
except ImportError:
    aioredis = None


class SessionInterfaceModel:
    """
    Model Of all the Session Interface.
    """
    def __init__(self, app=None, *args, **kwargs):
        self.app = app
        self._initialized = False

    def initialize(self, app=None):
        if self._initialized:
            return
        if app:
            self.app = app
        if not self.app:
            raise Exception(
                "FutureFinity Application is not set for this Interface.")
        self._initialized = True

    async def get_session(self, handler):
        raise NotImplementedError(
            "No Session Interface Can be automatically Selected.")

    async def write_session(self, handler, session_object):
        raise NotImplementedError(
            "No Session Interface Can be automatically Selected.")


class RedisSessionInterface(SessionInterfaceModel):
    def __init__(self, app=None, pool=None, *args, **kwargs):
        SessionInterfaceModel.__init__(self, app=app, *args,
                                       **kwargs)
        self.redis_connection_pool = pool

    def initialize(self, app=None, pool=None):
        SessionInterfaceModel.initialize(self, app=app)
        if pool:
            self.redis_connection_pool = pool
        if not self.redis_connection_pool:
            self.redis_connection_pool = self.app.settings.get(
                "redis_connection_pool", None)

    async def get_session(self, handler):
        if not self.redis_connection_pool:
            raise Exception(
                "Cannot found Redis Connection Pool. "
                "Please provide redis_connection_pool through Application "
                "Settings or __init__ pool Parameter.")
        session_id_cookie = handler.get_secure_cookie("_session_id")
        if not session_id_cookie:
            return {}

        session_id = json.loads(session_id_cookie)

        if session_id["type"] != "redis":
            return {}

        with (await self.redis_connection_pool) as conn:
            redis_key = "_%s_session" % session_id["id"]
            if not (await conn.exists(redis_key)):
                return {}
            return json.loads(ensure_str(await conn.get(redis_key)))

    async def write_session(self, handler, session_object):
        if session_object is None:
            return

        if not self.redis_connection_pool:
            raise Exception(
                "Cannot found Redis Connection Pool. "
                "Please provide redis_connection_pool through Application "
                "Settings or __init__ pool Parameter.")

        session_id = {
            "type": "redis",
            "id": str(uuid.uuid4())
        }
        handler.set_secure_cookie("_session_id", json.dumps(session_id))

        if session_object == {}:
            return

        with (await self.redis_connection_pool) as conn:
            redis_key = "_%s_session" % session_id["id"]
            conn.set(redis_key, json.dumps(session_object))


if aioredis is not None:
    DefaultSessionInterface = RedisSessionInterface
else:
    DefaultSessionInterface = SessionInterfaceModel
