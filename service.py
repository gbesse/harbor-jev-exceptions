"""Small authenticated HTTP decision service shared by the example adapters."""

from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3


class InputError(ValueError):
    pass


@contextmanager
def open_state(path):
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE IF NOT EXISTS decisions (id TEXT NOT NULL, policy_version TEXT NOT NULL, input_hash TEXT NOT NULL, choice TEXT NOT NULL, outcome TEXT NOT NULL, probability REAL NOT NULL, metadata TEXT NOT NULL, PRIMARY KEY(id, policy_version))"
    )
    try:
        yield db
    finally:
        db.close()


def decide(payload, adapter, policy, judge, db):
    parsed = adapter(payload)
    if parsed is None:
        return {"status": "ignored"}
    event_id, text, metadata = parsed
    if (
        not isinstance(event_id, str)
        or not 1 <= len(event_id) <= 160
        or not isinstance(text, str)
        or not text.strip()
        or len(text) > 16000
        or not isinstance(metadata, dict)
    ):
        raise InputError("invalid_input")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    row = db.execute(
        "SELECT input_hash,choice,outcome,probability,metadata FROM decisions WHERE id=? AND policy_version=?",
        (event_id, policy["version"]),
    ).fetchone()
    if row:
        if row[0] != digest or json.loads(row[4]) != metadata:
            raise InputError("id_conflict")
        return {
            "id": event_id,
            "policy_version": policy["version"],
            "choice": row[1],
            "outcome": row[2],
            "probability": row[3],
            "metadata": json.loads(row[4]),
            "cached": True,
        }
    if metadata.get("truncated") is True:
        result = {
            "choice": "other",
            "outcome": "review",
            "probability": 0.0,
            "policy_version": policy["version"],
        }
    else:
        result = judge(text)
    if (
        not isinstance(result, dict)
        or result.get("policy_version") != policy["version"]
        or result.get("outcome") not in {*policy["criteria"], "review"}
    ):
        raise ValueError("invalid_decision")
    db.execute(
        "INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",
        (
            event_id,
            policy["version"],
            digest,
            result["choice"],
            result["outcome"],
            result["probability"],
            json.dumps(metadata, sort_keys=True),
        ),
    )
    db.commit()
    return {"id": event_id, **result, "metadata": metadata, "cached": False}


def list_decisions(db, limit=50):
    rows = db.execute(
        "SELECT id,policy_version,choice,outcome,probability,metadata FROM decisions ORDER BY rowid DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {
            "id": row[0],
            "policy_version": row[1],
            "choice": row[2],
            "outcome": row[3],
            "probability": row[4],
            "metadata": json.loads(row[5]),
        }
        for row in rows
    ]


def make_app(
    adapter, policy, judge, state_path, token, *, signature_checker=None, max_body=65536
):
    if not isinstance(token, str) or len(token) < 16:
        raise ValueError("invalid_token")

    def app(environ, start_response):
        method, path = environ.get("REQUEST_METHOD"), environ.get("PATH_INFO")

        def reply(code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            start_response(
                code,
                [
                    ("Content-Type", "application/json; charset=utf-8"),
                    ("Content-Length", str(len(body))),
                ],
            )
            return [body]

        if method == "GET" and path == "/decisions":
            if not hmac.compare_digest(
                environ.get("HTTP_AUTHORIZATION", ""), "Bearer " + token
            ):
                return reply("401 Unauthorized", {"error": "unauthorized"})
            with open_state(state_path) as db:
                return reply("200 OK", {"decisions": list_decisions(db)})
        if method != "POST" or path != "/decide":
            return reply("404 Not Found", {"error": "not_found"})
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = -1
        if length < 1 or length > max_body:
            return reply("413 Payload Too Large", {"error": "invalid_size"})
        raw = environ["wsgi.input"].read(length)
        if len(raw) != length:
            return reply("400 Bad Request", {"error": "incomplete_body"})
        if signature_checker is None:
            authorized = hmac.compare_digest(
                environ.get("HTTP_AUTHORIZATION", ""), "Bearer " + token
            )
        else:
            authorized = signature_checker(raw, environ)
        if not authorized:
            return reply("401 Unauthorized", {"error": "unauthorized"})
        try:
            payload = json.loads(raw)
            with open_state(state_path) as db:
                result = decide(payload, adapter, policy, judge, db)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            InputError,
            KeyError,
            TypeError,
        ):
            return reply("400 Bad Request", {"error": "invalid_input"})
        except Exception:
            return reply("503 Service Unavailable", {"error": "decision_unavailable"})
        return reply("200 OK", result)

    return app
