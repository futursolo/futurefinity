import unittest
import nose2
import requests
import asyncio
import futurefinity.web
import functools


class PostTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False)

    def test_post_request(self):
        self.requests_result = None

        @self.app.add_handler("/post_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def post(self, *args, **kwargs):
                return self.get_body_arg("content")

        server = self.loop.run_until_complete(
            self.loop.create_server(self.app.make_server(), "127.0.0.1", 8888))

        async def get_requests_result(self):
            if not self.requests_result:
                await asyncio.sleep(1)  # Waiting for Server Initialized.
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        lambda: requests.post(
                            "http://127.0.0.1:8888/post_test",
                            data={"content": "Hello, World!"}
                        )
                    )
                )
            server.close()
            await server.wait_closed()
            self.loop.stop()
        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(self.requests_result.text, "Hello, World!")
