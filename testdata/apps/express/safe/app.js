// Orders service.
//
// Test fixture for creep. Do not deploy it or run it outside the creep sandbox.

"use strict";

const { execFile } = require("node:child_process");
const crypto = require("node:crypto");
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.use(express.json());

const client = new MongoClient("mongodb://127.0.0.1:27017");
const db = client.db("shop");
const settingsByUser = new Map();
const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

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
    if (BLOCKED_KEYS.has(key)) {
      continue;
    }
    const value = source[key];
    if (value && typeof value === "object") {
      const child = Object.hasOwn(target, key) ? target[key] : Object.create(null);
      target[key] = merge(child, value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

function verifyPassword(password, user) {
  const expected = Buffer.from(user.passwordHash, "hex");
  const actual = crypto.scryptSync(password, user.salt, expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string") {
    return res.sendStatus(400);
  }
  const user = await db.collection("users").findOne({ username: username });
  if (!user || !verifyPassword(password, user)) {
    return res.sendStatus(401);
  }
  return res.json({ session: crypto.randomUUID() });
});

app.get("/diagnostics/ping", requireUser, (req, res) => {
  const host = String(req.query.host || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(host)) {
    return res.sendStatus(400);
  }
  return execFile("ping", ["-c", "1", host], { timeout: 5000 }, (err, stdout) => {
    res.json({ ok: !err, output: stdout });
  });
});

app.get("/orders/:id", requireUser, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.sendStatus(400);
  }
  const order = await db.collection("orders").findOne({ _id: new ObjectId(req.params.id), ownerId: req.userId });
  if (!order) {
    return res.sendStatus(404);
  }
  return res.json(order);
});

app.patch("/settings", requireUser, (req, res) => {
  const current = settingsByUser.get(req.userId) || Object.create(null);
  settingsByUser.set(req.userId, merge(current, req.body));
  res.json(settingsByUser.get(req.userId));
});

module.exports = app;
