"""Inventory service.

Test fixture for creep. Do not deploy it or run it outside the creep sandbox.
"""

import os
import secrets
import sqlite3
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI()
DATABASE = "inventory.db"
SORT_COLUMNS = {"name": "name", "quantity": "quantity", "id": "id"}
WEBHOOK_HOSTS = {"hooks.example.invalid"}


class Item(BaseModel):
    name: str
    quantity: int


class Webhook(BaseModel):
    url: str


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def require_admin(x_admin_token: str = Header(default="")):
    expected = os.environ.get("INVENTORY_ADMIN_TOKEN", "")
    if not expected or not secrets.compare_digest(x_admin_token, expected):
        raise HTTPException(status_code=403)


@app.get("/items")
def list_items(sort: str = "name", conn: sqlite3.Connection = Depends(get_db)):
    column = SORT_COLUMNS.get(sort)
    if column is None:
        raise HTTPException(status_code=400)
    rows = conn.execute(f"SELECT id, name, quantity FROM items ORDER BY {column}").fetchall()
    return [dict(row) for row in rows]


@app.post("/items", dependencies=[Depends(require_admin)])
def create_item(item: Item, conn: sqlite3.Connection = Depends(get_db)):
    cur = conn.execute("INSERT INTO items (name, quantity) VALUES (?, ?)", (item.name, item.quantity))
    conn.commit()
    return {"id": cur.lastrowid}


@app.delete("/items/{item_id}", dependencies=[Depends(require_admin)])
def delete_item(item_id: int, conn: sqlite3.Connection = Depends(get_db)):
    conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    return {"deleted": item_id}


@app.post("/webhooks/test", dependencies=[Depends(require_admin)])
def test_webhook(hook: Webhook):
    if not hook.url.isprintable() or "\\" in hook.url or " " in hook.url:
        raise HTTPException(status_code=400)
    parts = urlsplit(hook.url)
    if parts.scheme != "https" or parts.netloc not in WEBHOOK_HOSTS:
        raise HTTPException(status_code=400)
    target = urlunsplit(("https", parts.netloc, parts.path or "/", parts.query, ""))
    resp = httpx.post(target, json={"event": "ping"}, timeout=5, follow_redirects=False)
    return {"status": resp.status_code}
