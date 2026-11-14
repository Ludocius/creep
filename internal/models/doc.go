// Package models speaks the HTTP model contract: OpenAI-compatible chat
// completions (OpenAI, Ollama, vLLM, LM Studio, Groq, OpenRouter) and the
// Anthropic messages API, with no provider SDK.
//
// It exists so that the rest of creep asks for "a JSON object of this shape"
// and gets back a closed Go struct, while every wire detail stays here:
//   - It never opens a connection. Every request is a gateway.Call sent
//     through a SendFunc, in production Through(egressLog, client), so
//     consent, the token budget, egress.log and the allowlisted dialer apply
//     (AGENTS.md invariants 1 and 2). The package cannot import net or
//     net/http; `make budget` enforces it.
//   - Each Call reserves the payload's byte count plus the request's output
//     cap, and that same cap is the request's max_tokens. A byte-level
//     tokenizer makes no more tokens than bytes, so this bounds the tokens of
//     what creep sends, but not provider-side overhead: an Anthropic forced
//     tool call adds about 350 input tokens, so a small call can report more
//     than it reserved. The gateway charges the reported usage after the
//     reply and refuses the next reservation, so a run can end at most that
//     overhead times the calls in flight past budget.max_tokens (#157).
//   - The API key comes only from CREEP_API_KEY (KeyFromEnv). It travels in
//     Call.Header, which the gateway never logs; Key never prints its value,
//     and no error quotes it or the endpoint.
//   - Model output is untrusted data (invariant 4). It is decoded into the
//     caller's closed struct with unknown fields refused, after a size cap,
//     and never executed. A reply that does not parse, is cut off, is a
//     refusal or fails the struct's Validate is retried at most Retries
//     times, each retry carrying the reason as context; then Complete
//     returns an *InvalidOutputError. The reason is creep's fixed text, which
//     never includes a key or value from the reply, except a caller's
//     Validate message, which is cut to 256 bytes of printable ASCII.
//   - Structured output uses what the endpoint supports: JSON schema, a GBNF
//     grammar (llama.cpp servers), a forced tool call, or the prompt alone.
//     Anthropic supports tools and prompt.
//
// Transport failures, non-2xx statuses, malformed envelopes, consent and
// budget refusals are not retried: they are the endpoint's or the user's
// problem, not the model's.
package models
