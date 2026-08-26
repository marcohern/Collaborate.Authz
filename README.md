# Collaborate Authorization Layer

Take-home submission. Two parts:

- **`DESIGN.md`** — the design document (Part 1): high-level architecture, implementation plan, testing,
  observability, failure modes/tradeoffs. A rendered, shareable version is in **`design-artifact.html`**.
- **`src/` + `tests/`** — the Part 2 slice: **Slice C, RFC 8693 on-behalf-of token exchange**, runnable
  with tests.
- **`SESSION.md`** — note on AI tooling used.

## Part 2 — what this slice is

An OAuth2 Authorization Server endpoint that turns *"I am service X, here is user U's identity"* into a
**narrow, audience-bound, attributable** token that lets X call **one** downstream **as** U — without X
being able to escalate. This is the on-behalf-of / confused-deputy problem from `DESIGN.md §2`.

### Endpoint contract — `POST /oauth2/token` (`application/x-www-form-urlencoded`)

```
grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
subject_token       = <JWT identifying the end user being acted for>
subject_token_type  = urn:ietf:params:oauth:token-type:jwt
actor_token         = <JWT of the acting client/service>
actor_token_type    = urn:ietf:params:oauth:token-type:jwt
audience            = DocumentService            # REQUIRED (deliberate deviation, see below)
scope               = doc.read                   # requested; may be narrowed
```

Success → RFC 8693 response:

```json
{ "access_token": "<jwt>", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer", "expires_in": 120, "scope": "doc.read" }
```

The minted JWT carries: `sub` = end user, `act.sub` = acting party (audit chain), `aud` = the one
downstream, `scope` = the narrowed grant, `auth_version` = revocation epoch.

Failures use OAuth error codes: `invalid_request`, `invalid_client` (401), `unauthorized_client` (403),
`invalid_target`, `invalid_scope`, `invalid_grant`.

`GET /.well-known/jwks.json` publishes the public key so a real downstream could validate offline.

### The other endpoints

- **`POST /oauth2/login`** (`application/json`, anonymous) — dev password login (`admin` / `Admin123`)
  that mints an identity token, so the protected endpoints below can be exercised without a real IdP.
  Returns `{ accessToken, refreshToken, expires, scope }`.
- **`GET /api/PrivateValues`** and **`GET /api/me`** — bearer-protected resources. Both are marked
  `[RequireBearerToken]`, so `BearerTokenMiddleware` validates the `Authorization: Bearer <jwt>` header
  against the same `InboundTokenValidator` the exchange uses; without a valid token they answer `401`
  with `{ "error": "invalid_token" }`. `/api/me` echoes the principal's claims, which is what proves the
  minted token round-trips.

### The confused-deputy guards (each maps to a test)

1. **`audience` is required** → refuse to mint an unrestricted token.
2. **Scope = `requested ∩ subject-permissions ∩ actor-grant ∩ audience-allowed`** → never trust requested
   scope; subject permissions come from the PDP, not from caller-supplied claims.
3. **Actor must be a registered client scoped to the subject's firm** → no cross-firm delegation.
4. **Revocation epoch** → a still-signed, unexpired-but-revoked identity is rejected.

## Design decisions & tradeoffs (why this approach)

- **Use the standard, not a bespoke scheme.** RFC 8693 Token Exchange with the `act` claim is the
  spec-blessed answer to delegation + attribution. Reaching for it (vs. inventing a header/format) is the
  senior move.
- **Lean on the framework for all crypto/token handling.** `JsonWebTokenHandler` +
  `TokenValidationParameters` verify inbound signatures/issuer/lifetime; `SecurityTokenDescriptor` +
  `SigningCredentials` build and RS256-sign the outbound token. **No hand-rolled cryptography or parsing.**
- **Where I *did* write custom code, and why:** only the business-authorization logic — downscoping,
  actor-trust, and the epoch check. That's exactly the part a framework can't know; it's the point of the
  exercise.
- **Why not the JwtBearer middleware for the inbound tokens?** In a token-exchange request the tokens
  arrive in the **form body** (RFC 8693), not the `Authorization` header, so the `[Authorize]` pipeline
  isn't the right fit. I validate them explicitly with the same underlying handler and validation
  parameters — same guarantees, correct shape for this endpoint. (A resource endpoint *would* use
  `AddJwtBearer` + policies — that's Slice A.)

### Deliberate deviations from RFC 8693

- **`audience` is mandatory** (spec makes it optional). An audience-less token is the classic confused-
  deputy vector; a multi-tenant AS should never mint one.
- **Always downscope to the intersection** rather than honoring `requested scope`. Least privilege by default.

Both are called out in code comments where they're enforced (`TokenExchangeHandler`).

### Stubs (so it runs without external infra)

- `InMemoryPermissionStore` — stands in for the Redis PDP (`IPermissionStore` is Redis-shaped).
- `ActorTrustPolicy` / `DownstreamRegistry` — stand in for per-firm client config and the service registry.
- `SigningKeyProvider` — dev RSA key generated in-process. **Production uses AWS KMS with rotation** (see
  `DESIGN.md §3`). No real IdP: test subject/actor tokens are signed with the same dev key.

## Build, test, run

Requires the .NET SDK (built and tested on 10.0).

```bash
dotnet build Collaborate.Authz.sln     # compiles clean
dotnet test                            # 9 xUnit integration tests (allow, downscope, + each reject path)
dotnet run --project src/Collaborate.Authz --urls http://localhost:5199
```

Quick smoke (no token needed — shows the guards):

```bash
curl http://localhost:5199/.well-known/jwks.json
curl -X POST http://localhost:5199/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=x&actor_token=y"
# -> {"error":"invalid_target","error_description":"audience is required; ..."}
```

A full happy-path exchange needs valid subject/actor JWTs signed by the dev key; `TokenExchangeTests`
mints them (`TestTokens`) and asserts the minted token's `sub` / `act.sub` / `aud` / `scope` /
`auth_version` cryptographically.

### Manual happy-path exchange

The service signs with `dev-signing-key.pem` (repo root) when that file is present, so tokens can also be
minted out-of-process. With the service running:

```powershell
.\tools\get-token.ps1                                  # emp-1 via client-sys-a -> DocumentService, doc.read
.\tools\get-token.ps1 -Scope "doc.read doc.write"      # downscoped back to doc.read
.\tools\get-token.ps1 -Subject emp-2                   # 403 — actor cannot cross firms
.\tools\get-token.ps1 -AuthVersion 0                   # 400 — stale revocation epoch
```

`tools/mint-token.cs` mints a single identity token if you'd rather drive the endpoint by hand
(`dotnet run tools/mint-token.cs -- <sub> [authVersion] [lifetimeSeconds]`).

Seeded fixtures: subjects `emp-1` (firm-a: `doc.read`, `comment.read`) and `emp-2` (firm-b: `doc.read`);
actor `client-sys-a` (firm-a, may delegate `doc.read`/`doc.write`); audiences `DocumentService` (`doc.*`)
and `CommentsService` (`comment.*`).

## Layout

```
DESIGN.md · design-artifact.html · SESSION.md
src/Collaborate.Authz/
  Program.cs                         # DI + pipeline (/.well-known/jwks.json, /api/me)
  Controllers/
    Oauth2Controller.cs              # POST /oauth2/token (exchange), POST /oauth2/login
    PrivateValuesController.cs       # GET /api/PrivateValues, bearer-protected
  TokenExchange/
    TokenExchangeHandler.cs          # the ordered guards (core logic)
    JwtTokenMinter.cs                # mints the narrowed act-chain token
    IPermissionStore + InMemory...   # PDP stub (Redis-shaped)
    IActorTrustPolicy + ActorTrust   # delegation-client registry
    IDownstreamRegistry + Downstream # audience -> allowed scopes
    TokenConstants.cs                # RFC 8693 URNs + issuer
  Security/
    SigningKeyProvider.cs            # dev RSA key + JWK projection
    InboundTokenValidator.cs         # framework validation of subject/actor tokens
tests/Collaborate.Authz.Tests/
    TokenExchangeTests.cs            # end-to-end, incl. crypto verification of minted tokens
    TestTokens.cs                    # signs stand-in subject/actor identity tokens
```
