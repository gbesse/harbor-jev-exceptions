import copy
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from app import adapt, make_harbor_app
from jev import normalize
from service import InputError


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.case = json.loads(Path("examples/case.json").read_text())

    def test_scan_and_justification_create_stable_dossier(self):
        first = adapt(self.case)
        second = adapt(self.case)
        self.assertEqual(first, second)
        self.assertEqual(first[2]["vulnerabilities"], 3)
        self.assertNotIn("justification", first[2])

    def test_incomplete_scan_is_rejected(self):
        case = copy.deepcopy(self.case)
        report = next(
            iter(case["scan"]["event_data"]["resources"][0]["scan_overview"].values())
        )
        report["scan_status"] = "Error"
        with self.assertRaises(InputError):
            adapt(case)

    def test_missing_mitigation_is_rejected(self):
        case = copy.deepcopy(self.case)
        case["exception"]["mitigations"] = []
        with self.assertRaises(InputError):
            adapt(case)

    def test_webhook_to_human_review_flow(self):
        policy = json.loads(Path("examples/policy.json").read_text())
        choice = next(iter(policy["criteria"]))
        judge = Mock(return_value=normalize(choice, 0.97, policy))
        with tempfile.TemporaryDirectory() as folder:
            state = str(Path(folder) / "state.sqlite")
            app = make_harbor_app(
                policy, judge, state, "webhook-token-1234", "review-token-12345"
            )

            def call(path, payload=None, token="review-token-12345", method="POST"):
                raw = json.dumps(payload).encode() if payload is not None else b""
                status = []
                response = b"".join(
                    app(
                        {
                            "REQUEST_METHOD": method,
                            "PATH_INFO": path,
                            "HTTP_AUTHORIZATION": "Bearer " + token,
                            "CONTENT_LENGTH": str(len(raw)),
                            "wsgi.input": io.BytesIO(raw),
                        },
                        lambda code, headers: status.append(code),
                    )
                )
                return status[0], json.loads(response)

            self.assertEqual(call("/scan", self.case["scan"])[0], "401 Unauthorized")
            self.assertEqual(
                call("/review", {"scan_id": "missing"})[0], "400 Bad Request"
            )
            code, scan = call("/scan", self.case["scan"], "webhook-token-1234")
            self.assertEqual(code, "202 Accepted")
            code, listing = call("/scans", method="GET")
            self.assertEqual(code, "200 OK")
            self.assertEqual(listing["scans"][0]["id"], scan["scan_id"])
            case = {"scan_id": scan["scan_id"], "exception": self.case["exception"]}
            code, first = call("/review", case)
            self.assertEqual(code, "200 OK")
            self.assertFalse(first["cached"])
            self.assertTrue(call("/review", case)[1]["cached"])
            self.assertEqual(judge.call_count, 1)
            with sqlite3.connect(state) as db:
                dump = "\n".join(db.iterdump())
            self.assertNotIn(self.case["exception"]["justification"], dump)
