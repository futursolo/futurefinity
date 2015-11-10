import unittest
import nose2
import requests
import asyncio
import futurefinity.web
import functools
import traceback


class GetTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False)

    def test_custom_header_request(self):
        @self.app.add_handler("/header_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                self.set_header("content", self.get_header("content"))
                return "Hello, World!"

        server = self.loop.run_until_complete(
            self.loop.create_server(self.app.make_server(), "127.0.0.1", 8888))

        async def get_requests_result(self):
            try:
                await asyncio.sleep(1)  # Waiting for Server Initialized.
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        lambda: requests.get(
                            "http://127.0.0.1:8888/header_test",
                            headers={"content": "Hello, World!"}
                        )
                    )
                )
            except:
                traceback.print_exc()
            finally:
                server.close()
                await server.wait_closed()
                self.loop.stop()

        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(self.requests_result.text, "Hello, World!")
