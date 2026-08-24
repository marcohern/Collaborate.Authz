# AI Tooling — Session Note

This submission was produced with **Claude Code** (Anthropic) as a pair-programming assistant.

## How AI was used

- **Framing & clarification.** At the start I had the assistant confirm the deliverable shape and the few
  decisions that materially change the output — which Part 2 slice to build (chose **C, OBO token
  exchange**), how complete the code should be (**runnable + tests**), and the doc format. That kept the
  work inside the 2–3 hour budget instead of guessing.
- **Design.** The two-tier model (coarse claims in the token / fine-grained + revocation epoch in a Redis
  PDP), the RFC 8693 confused-deputy guards, and the failure-mode tradeoffs are the substance of `DESIGN.md`.
  AI was used to draft and tighten prose, not to invent the architecture wholesale.
- **Implementation.** The assistant scaffolded the ASP.NET Core project and wrote the handler, minter,
  stubs, and xUnit tests, then **built and ran them** (`dotnet build` / `dotnet test` → 9/9 green) and
  smoke-tested the hosted endpoints (`/.well-known/jwks.json`, error paths) via `curl`. Nothing here is
  claimed to work that wasn't executed.

## Judgment kept human / explicit

- Chose to **lean on the framework** for all crypto/token handling and to write custom code only for the
  business-authorization logic — and to say so explicitly (the exercise flags this as a scoring axis).
- Chose two **deliberate deviations** from RFC 8693 (mandatory `audience`, always downscope) and documented
  the security reasoning rather than silently following or breaking spec.
- Kept scope to **one** slice with depth, per the brief, rather than sketching all three.
