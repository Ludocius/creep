"""Notes service.

Test fixture for creep. Do not deploy it or run it outside the creep sandbox.
"""

import sqlite3
from urllib.parse import urlsplit, urlunsplit

import requests
from flask import Flask, abort, g, jsonify, request, send_from_directory

app = Flask(__name__)
DATABASE = "notes.db"
UPLOAD_DIR = "/srv/notes/uploads"
PREVIEW_HOSTS = {"links.example.invalid"}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def current_user_id():
    # An upstream proxy authenticates the user and sets this header.
    user = request.headers.get("X-User-Id", "")
    if not user.isdigit():
        abort(401)
    return int(user)


@app.get("/notes/search")
def search_notes():
    owner = current_user_id()
    term = request.args.get("q", "")
    query = "SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ?"
    rows = db().execute(query, (owner, f"%{term}%")).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/notes/<int:note_id>")
def get_note(note_id):
    owner = current_user_id()
    row = db().execute(
        "SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?", (note_id, owner)
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@app.post("/notes/preview")
def preview_link():
    current_user_id()
    url = request.get_json(force=True).get("url", "")
    if not url.isprintable() or "\\" in url or " " in url:
        abort(400)
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in PREVIEW_HOSTS:
        abort(400)
    target = urlunsplit(("https", parts.netloc, parts.path or "/", parts.query, ""))
    resp = requests.get(target, timeout=5, allow_redirects=False)
    return jsonify({"status": resp.status_code, "length": len(resp.content)})


@app.get("/attachments/<path:name>")
def download_attachment(name):
    current_user_id()
    return send_from_directory(UPLOAD_DIR, name)
