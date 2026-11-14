"""Notes service.

Test fixture for creep. Do not deploy it or run it outside the creep sandbox.
"""

import os
import sqlite3

import requests
from flask import Flask, abort, g, jsonify, request, send_file

app = Flask(__name__)
DATABASE = "notes.db"
UPLOAD_DIR = "/srv/notes/uploads"


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
    query = f"SELECT id, title FROM notes WHERE owner_id = {owner} AND title LIKE '%{term}%'"
    rows = db().execute(query).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/notes/<int:note_id>")
def get_note(note_id):
    current_user_id()
    row = db().execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@app.post("/notes/preview")
def preview_link():
    current_user_id()
    url = request.get_json(force=True).get("url", "")
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "length": len(resp.content)})


@app.get("/attachments/<path:name>")
def download_attachment(name):
    current_user_id()
    return send_file(os.path.join(UPLOAD_DIR, name))
