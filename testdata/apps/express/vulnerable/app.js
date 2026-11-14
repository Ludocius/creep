// Orders service.
//
// Test fixture for creep. Do not deploy it or run it outside the creep sandbox.

"use strict";

const { exec } = require("node:child_process");
const crypto = require("node:crypto");
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.use(express.json());

const client = new MongoClient("mongodb://127.0.0.1:27017");
const db = client.db("shop");
const settingsByUser = new Map();

// An upstream proxy authenticates the user and sets this header.
function requireUser(req, res, next) {
  const id = req.get("x-user-id");
  if (!id || !/^[a-f0-9]{24}$/.test(id)) {
    return res.sendStatus(401);
  }
  req.userId = id;
  return next();
}

function merge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === "object") {
      target[key] = merge(target[key] || {}, value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await db.collection("users").findOne({ username: username, password: password });
  if (!user) {
    return res.sendStatus(401);
  }
  return res.json({ session: crypto.randomUUID() });
});

app.get("/diagnostics/ping", requireUser, (req, res) => {
  const host = String(req.query.host || "");
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout) => {
    res.json({ ok: !err, output: stdout });
  });
});

app.get("/orders/:id", requireUser, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.sendStatus(400);
  }
  const order = await db.collection("orders").findOne({ _id: new ObjectId(req.params.id) });
  if (!order) {
    return res.sendStatus(404);
  }
  return res.json(order);
});

app.patch("/settings", requireUser, (req, res) => {
  const current = settingsByUser.get(req.userId) || {};
  settingsByUser.set(req.userId, merge(current, req.body));
  res.json(settingsByUser.get(req.userId));
});

module.exports = app;
