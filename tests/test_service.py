import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from app import adapt
from jev import normalize
from service import decide, list_decisions, make_app, open_state


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(Path("examples/policy.json").read_text())
        example = next(
            path
            for path in Path("examples").glob("*.json")
            if path.name != "policy.json"
        )
        self.event = json.loads(example.read_text())
        self.choice = next(iter(self.policy["criteria"]))

    def test_decision_cache_and_no_raw_text_storage(self):
        judge = Mock(return_value=normalize(self.choice, 0.97, self.policy))
        with open_state(":memory:") as db:
            first = decide(self.event, adapt, self.policy, judge, db)
            second = decide(self.event, adapt, self.policy, judge, db)
            stored = list_decisions(db)
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(judge.call_count, 1)
        self.assertEqual(len(stored), 1)
        self.assertNotIn("text", json.dumps(stored))

    def test_http_auth_cache_and_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            state = str(Path(folder) / "state.sqlite")
            judge = Mock(return_value=normalize(self.choice, 0.97, self.policy))
            app = make_app(adapt, self.policy, judge, state, "0123456789abcdef")
            raw = json.dumps(self.event).encode()

            def call(method, auth, path="/decide"):
                status = []
                environ = {
                    "REQUEST_METHOD": method,
                    "PATH_INFO": path,
                    "HTTP_AUTHORIZATION": auth,
                    "CONTENT_LENGTH": str(len(raw)),
                    "wsgi.input": io.BytesIO(raw),
                }
                output = b"".join(
                    app(environ, lambda code, headers: status.append(code))
                )
                return status[0], json.loads(output)

            self.assertEqual(call("POST", "")[0], "401 Unauthorized")
            code, first = call("POST", "Bearer 0123456789abcdef")
            self.assertEqual(code, "200 OK")
            self.assertFalse(first["cached"])
            self.assertTrue(call("POST", "Bearer 0123456789abcdef")[1]["cached"])
            self.assertEqual(judge.call_count, 1)
            self.assertEqual(
                len(
                    call("GET", "Bearer 0123456789abcdef", "/decisions")[1]["decisions"]
                ),
                1,
            )

            failed = make_app(
                adapt,
                self.policy,
                Mock(side_effect=OSError("offline")),
                str(Path(folder) / "failed.sqlite"),
                "0123456789abcdef",
            )
            status = []
            environ = {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": "/decide",
                "HTTP_AUTHORIZATION": "Bearer 0123456789abcdef",
                "CONTENT_LENGTH": str(len(raw)),
                "wsgi.input": io.BytesIO(raw),
            }
            b"".join(failed(environ, lambda code, headers: status.append(code)))
            self.assertEqual(status[0], "503 Service Unavailable")


if __name__ == "__main__":
    unittest.main()
