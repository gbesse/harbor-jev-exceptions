"""Prepare advisory Harbor scan exception dossiers without changing allowlists."""

import argparse
import hashlib
import hmac
import json
import os
import re
from wsgiref.simple_server import make_server

from jev import evaluate, normalize
from service import InputError, decide, make_app, open_state

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def parse_scan(scan):
    if not isinstance(scan, dict) or scan.get("type") != "SCANNING_COMPLETED":
        raise InputError("invalid_scan")
    event_data = scan.get("event_data")
    if not isinstance(event_data, dict) or not isinstance(
        event_data.get("repository"), dict
    ):
        raise InputError("invalid_scan")
    resources = event_data.get("resources")
    if (
        not isinstance(resources, list)
        or len(resources) != 1
        or not isinstance(resources[0], dict)
    ):
        raise InputError("invalid_scan")
    resource = resources[0]
    digest = resource.get("digest")
    repo = event_data["repository"].get("repo_full_name")
    if (
        not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or not isinstance(repo, str)
        or not repo
        or len(repo) > 500
    ):
        raise InputError("invalid_scan")
    overview = resource.get("scan_overview")
    if not isinstance(overview, dict) or len(overview) != 1:
        raise InputError("invalid_scan")
    report_type, report = next(iter(overview.items()))
    if not isinstance(report_type, str) or not 1 <= len(report_type) <= 200:
        raise InputError("invalid_scan")
    if not isinstance(report, dict) or report.get("scan_status") != "Success":
        raise InputError("scan_incomplete")
    summary = report.get("summary")
    if (
        not isinstance(summary, dict)
        or isinstance(summary.get("total"), bool)
        or not isinstance(summary.get("total"), int)
        or summary["total"] < 0
    ):
        raise InputError("invalid_scan")
    severity = report.get("severity")
    if not isinstance(severity, str) or len(severity) > 40:
        raise InputError("invalid_scan")
    minimal = {
        "type": "SCANNING_COMPLETED",
        "event_data": {
            "repository": {"repo_full_name": repo},
            "resources": [
                {
                    "digest": digest,
                    "scan_overview": {
                        report_type: {
                            "scan_status": "Success",
                            "severity": severity,
                            "summary": {"total": summary["total"]},
                        }
                    },
                }
            ],
        },
    }
    metadata = {
        "repository": repo,
        "digest": digest,
        "vulnerabilities": summary["total"],
        "severity": severity,
    }
    return minimal, metadata


def adapt(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("scan"), dict):
        raise InputError("invalid_case")
    scan, exception = payload["scan"], payload.get("exception")
    _, metadata = parse_scan(scan)
    if not isinstance(exception, dict):
        raise InputError("invalid_exception")
    justification = exception.get("justification")
    workload = exception.get("workload")
    mitigations = exception.get("mitigations")
    if (
        not isinstance(justification, str)
        or not justification.strip()
        or len(justification) > 4000
        or not isinstance(workload, str)
        or not workload.strip()
        or len(workload) > 500
        or not isinstance(mitigations, list)
        or not 1 <= len(mitigations) <= 10
        or any(
            not isinstance(x, str) or not x.strip() or len(x) > 300 for x in mitigations
        )
    ):
        raise InputError("invalid_exception")
    text = (
        f"Repository: {metadata['repository']}\nImage digest: {metadata['digest']}\n"
        f"Scan severity: {metadata['severity']}\n"
        f"Vulnerabilities total: {metadata['vulnerabilities']}\nWorkload: {workload}\n"
        f"Exception justification: {justification}\nMitigations: "
        + "; ".join(mitigations)
    )
    event_id = "case:" + hashlib.sha256(text.encode()).hexdigest()
    return event_id, text, metadata


def record_scan(scan, db):
    minimal, metadata = parse_scan(scan)
    scan_id = (
        "scan:"
        + hashlib.sha256(json.dumps(minimal, sort_keys=True).encode()).hexdigest()
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, repository TEXT NOT NULL, digest TEXT NOT NULL, severity TEXT NOT NULL, vulnerabilities INTEGER NOT NULL, payload TEXT NOT NULL)"
    )
    db.execute(
        "INSERT OR IGNORE INTO scans VALUES(?,?,?,?,?,?)",
        (
            scan_id,
            metadata["repository"],
            metadata["digest"],
            metadata["severity"],
            metadata["vulnerabilities"],
            json.dumps(minimal, sort_keys=True),
        ),
    )
    db.commit()
    return scan_id


def make_harbor_app(policy, judge, state_path, webhook_token, review_token):
    if not all(
        isinstance(t, str) and len(t) >= 16 for t in (webhook_token, review_token)
    ):
        raise ValueError("invalid_token")
    base = make_app(adapt, policy, judge, state_path, review_token)

    def app(environ, start_response):
        method, path = environ.get("REQUEST_METHOD"), environ.get("PATH_INFO")
        if path in ("/decide", "/decisions"):
            return base(environ, start_response)

        def reply(code, obj):
            body = json.dumps(obj).encode()
            start_response(
                code,
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                ],
            )
            return [body]

        if (method, path) not in (
            ("POST", "/scan"),
            ("POST", "/review"),
            ("GET", "/scans"),
        ):
            return reply("404 Not Found", {"error": "not_found"})
        expected = webhook_token if path == "/scan" else review_token
        if not hmac.compare_digest(
            environ.get("HTTP_AUTHORIZATION", ""), "Bearer " + expected
        ):
            return reply("401 Unauthorized", {"error": "unauthorized"})
        if method == "GET":
            with open_state(state_path) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, repository TEXT NOT NULL, digest TEXT NOT NULL, severity TEXT NOT NULL, vulnerabilities INTEGER NOT NULL, payload TEXT NOT NULL)"
                )
                rows = db.execute(
                    "SELECT id,repository,digest,severity,vulnerabilities FROM scans ORDER BY rowid DESC LIMIT 50"
                ).fetchall()
            return reply(
                "200 OK",
                {
                    "scans": [
                        dict(
                            zip(
                                (
                                    "id",
                                    "repository",
                                    "digest",
                                    "severity",
                                    "vulnerabilities",
                                ),
                                row,
                            )
                        )
                        for row in rows
                    ]
                },
            )
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
            if not 1 <= length <= 65536:
                return reply("413 Payload Too Large", {"error": "invalid_size"})
            raw = environ["wsgi.input"].read(length)
            if len(raw) != length:
                raise InputError("incomplete_body")
            payload = json.loads(raw)
            with open_state(state_path) as db:
                if path == "/scan":
                    result = {"scan_id": record_scan(payload, db)}
                else:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, repository TEXT NOT NULL, digest TEXT NOT NULL, severity TEXT NOT NULL, vulnerabilities INTEGER NOT NULL, payload TEXT NOT NULL)"
                    )
                    scan_id = (
                        payload.get("scan_id") if isinstance(payload, dict) else None
                    )
                    if not isinstance(scan_id, str):
                        raise InputError("invalid_scan_id")
                    row = db.execute(
                        "SELECT payload FROM scans WHERE id=?", (scan_id,)
                    ).fetchone()
                    if not row:
                        raise InputError("unknown_scan_id")
                    result = decide(
                        {
                            "scan": json.loads(row[0]),
                            "exception": payload.get("exception"),
                        },
                        adapt,
                        policy,
                        judge,
                        db,
                    )
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return reply("400 Bad Request", {"error": "invalid_input"})
        except Exception:
            return reply("503 Service Unavailable", {"error": "decision_unavailable"})
        return reply("202 Accepted" if path == "/scan" else "200 OK", result)

    return app


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--state", default=".local/decisions.sqlite")
    args = parser.parse_args()
    with open("examples/policy.json", encoding="utf-8") as source:
        policy = json.load(source)
    if args.demo:
        with open("examples/case.json", encoding="utf-8") as source:
            case = json.load(source)
        with open_state(":memory:") as db:
            print(
                json.dumps(
                    decide(
                        case,
                        adapt,
                        policy,
                        lambda _: normalize("weak", 0.97, policy),
                        db,
                    ),
                    indent=2,
                )
            )
        return
    key = os.environ["TYPESAFE_API_KEY"]
    app = make_harbor_app(
        policy,
        lambda text: evaluate(text, policy, key),
        args.state,
        os.environ["HARBOR_WEBHOOK_TOKEN"],
        os.environ["JEV_REVIEW_TOKEN"],
    )
    with make_server("127.0.0.1", int(os.environ.get("PORT", "8098")), app) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
