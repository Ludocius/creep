# creep report

creep `v0.0.0-test` (commit `0000000`) · report schema 1

**Run complete.** Every planned step and file was evaluated, except the files listed under Not evaluated.

## Findings

| ID | Class | Status | Location |
|---|---|---|---|
| `f1` | `sqli` | `verified` | `app/db.py:12` |
| `f2` | `path_traversal` | `probable` | ``app/`tick`\|pipe.py:7`` |
| `f5` | `command_injection` | `probable` | `bad\xffutf8 #?%.py` |
| `f3` | `sqli` | `discarded` | `app/db.py:40` |
| `f4` | `ssrf` | `not evaluated` | `svc/fetch.js:9` |

Run `creep why <id>` for the evidence behind a finding.

## Coverage by class

| Class | Status | Calibration detected / tasks | Recall 95% CI |
|---|---|---|---|
| `sqli` | `covered` | 9 / 10 | 0.596 – 0.982 |
| `path_traversal` | `partial` | 3 / 6 | 0.188 – 0.812 |
| `ssrf` | `not evaluated` | 0 / 0 | 0.000 – 1.000 |

## Not evaluated

5 files were not evaluated; nothing in them is covered by this report.

| File | Reason |
|---|---|
| `www.evil.example/[link](http://x)<script>.js` | `too large` |
| `ok\x1b[31mred\x0anewline.py` | `line too long` |
| `bidi\u202egnp.exe` | `read failed` |
| `c1\x9b31mcsi.py` | `redact failed` |
| `del\x7fete.py` | `read failed` |

## Data handling

3 requests, 2050 bytes after redaction, sent to 2 endpoints (from `egress.log`; each payload is in `payloads/`).

| Endpoint | Models | Requests | Bytes | Tokens in / out | Outcomes |
|---|---|---|---|---|---|
| `http://127.0.0.1:8080/v1/chat/completions` | `local\|model` | 1 | 50 | 0 / 0 | `http_error` 1 |
| `https://api.example.com/v1/messages` | `m-large`, `m-small` | 2 | 2000 | 300 / 40 | `no_result` 1, `ok` 1 |

Redacted before sending: `AWS_KEY` 3, `EMAIL` 1.
