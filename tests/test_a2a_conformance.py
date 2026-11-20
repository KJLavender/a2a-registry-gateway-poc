"""A2A 1.0 details the official TCK (github.com/a2aproject/a2a-tck) caught in poc/agents/base.py.

The full TCK runs in CI against `python -m poc.tck_sut`; these tests keep the fixes without needing it.
"""
from __future__ import annotations

import time
import unittest

from poc import tck_sut
from poc.common.web import free_port, http, serve

URL = ""
SERVER = None


def setUpModule() -> None:
    global URL, SERVER
    port = free_port()
    URL = f"http://127.0.0.1:{port}"
    SERVER = serve(tck_sut.build(URL), "127.0.0.1", port)


def tearDownModule() -> None:
    SERVER.shutdown()
    SERVER.server_close()


def rpc(method: str, params: dict, path: str = "/a2a") -> dict:
    status, body, _ = http("POST", URL + path, json_body={"jsonrpc": "2.0", "id": 1, "method": method,
                                                          "params": params},
                           headers={"A2A-Version": "1.0", "Authorization": "Bearer tck"})
    return body


def send(message_id: str, **config) -> dict:
    return rpc("SendMessage", {"message": {"messageId": message_id, "role": "ROLE_USER", "parts": [{"text": "hi"}]},
                               "configuration": config})


class Conformance(unittest.TestCase):
    def test_trailing_slash_endpoint(self):
        self.assertIn("result", rpc("SendMessage", {"message": {"messageId": "tck-complete-task-1", "role": "ROLE_USER",
                                                                 "parts": [{"text": "hi"}]}}, path="/a2a/"))

    def test_original_proto_field_names_are_accepted(self):
        task = send("tck-complete-task-2")["result"]["task"]
        got = rpc("GetTask", {"id": task["id"], "history_length": 1})["result"]
        self.assertLessEqual(len(got["history"]), 1)

    def test_known_methods_we_do_not_offer(self):
        self.assertEqual(rpc("SendStreamingMessage", {})["error"]["code"], -32004)
        self.assertEqual(rpc("GetExtendedAgentCard", {})["error"]["code"], -32004)
        self.assertEqual(rpc("CreateTaskPushNotificationConfig", {})["error"]["code"], -32003)
        self.assertEqual(rpc("NoSuchMethod", {})["error"]["code"], -32601)

    def test_unsupported_media_type(self):
        body = rpc("SendMessage", {"message": {"messageId": "m", "role": "ROLE_USER",
                                               "parts": [{"raw": "dGNr", "mediaType": "application/x-nope"}]}})
        self.assertEqual(body["error"]["code"], -32005)

    def test_direct_message_and_rejected_task(self):
        self.assertEqual(send("tck-message-response-1")["result"]["message"]["parts"][0]["text"],
                         "Direct message response")
        task = send("tck-reject-task-1")["result"]["task"]
        self.assertEqual(task["status"]["state"], "TASK_STATE_REJECTED")

    def test_agent_card_is_cacheable(self):
        status, _, headers = http("GET", f"{URL}/.well-known/agent-card.json")
        self.assertEqual(status, 200)
        self.assertIn("max-age", headers["cache-control"])
        status, _, _ = http("GET", f"{URL}/.well-known/agent-card.json", headers={"If-None-Match": headers["etag"]})
        self.assertEqual(status, 304)


if __name__ == "__main__":
    unittest.main()
