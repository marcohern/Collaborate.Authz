# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An authorization-layer take-home for Caseware Collaborate. Two parts:

- **Design doc** — `DESIGN.md` (source) and `design-artifact.html` (rendered, shareable). Covers OIDC login,
  a two-tier permission model, and on-behalf-of delegation.
- **Code slice** — a runnable ASP.NET Core service implementing **Slice C: RFC 8693 on-behalf-of token
  exchange**. This is the only code in the repo; it is one deliberately-scoped slice, not a full app.

The IdP itself (credentials, MFA) is explicitly out of scope — this repo is the authorization layer *around*
an assumed IdP. Keep that boundary: don't add user/credential storage.

## Commands

Built and tested on **.NET SDK 10** (projects target `net10.0`). If a reviewer is on .NET 8, retarget by
changing `<TargetFramework>` in both `.csproj` files — no code changes needed.

```bash
dotnet build Collaborate.Authz.sln          # build everything
dotnet test                                 # run the full xUnit suite (9 integration tests)
dotnet test --filter "FullyQualifiedName~Revoked"   # run a single test by name substring
dotnet run --project src/Collaborate.Authz --urls http://localhost:5199   # host the service
```

There is no separate lint step; treat build warnings as the bar (currently builds clean with 0 warnings).

## Architecture

Request flow for the one endpoint that matters, `POST /oauth2/token` (RFC 8693 token-exchange grant):

`Program.cs` (DI + endpoint mapping) → `TokenExchange/TokenExchangeHandler.cs` (all the logic) → collaborators.

`TokenExchangeHandler.HandleAsync` is the heart of the repo. It runs a **fixed, ordered sequence of guards**,
and each guard maps 1:1 to a test in `tests/.../TokenExchangeTests.cs`. The order is load-bearing (e.g. the
revocation-epoch check runs before actor-trust). When editing the handler, preserve the ordering and keep the
test-per-guard correspondence.

The guards, and the collaborators they consult:

- **Inbound token validation** — `Security/InboundTokenValidator.cs`. Validates `subject_token` and
  `actor_token` via the framework's `JsonWebTokenHandler` + `TokenValidationParameters`. Note: it does **not**
  use the JwtBearer middleware, because RFC 8693 tokens arrive in the form body, not the `Authorization`
  header. Read claims from `TokenValidationResult.Claims` (the raw, unmapped payload), not `ClaimsIdentity`.
- **Subject permissions** — `IPermissionStore` (`InMemoryPermissionStore` stub). This is the source of truth
  for what the subject may do. **The endpoint never trusts scopes from the caller's tokens** — it reads them
  here. In the design this is the Redis PDP; the interface is intentionally Redis-shaped.
- **Actor trust** — `IActorTrustPolicy` (`ActorTrustPolicy` stub). The actor must be a registered delegation
  client whose `FirmId` matches the subject's firm. This is the cross-firm confused-deputy guard.
- **Audience + scope** — `IDownstreamRegistry` (`DownstreamRegistry` stub) plus
  `ComputeGrantedScopes`. Granted scope = `requested ∩ subject-permissions ∩ actor-grant ∩ audience-allowed`.
- **Minting** — `JwtTokenMinter` (behind `ITokenMinter`) RS256-signs the narrowed token via
  `SecurityTokenDescriptor` + `SigningKeyProvider`.

`SigningKeyProvider` (registered as a **singleton**) generates one in-process RSA key. The same instance signs
outbound tokens and validates inbound ones, so the demo is a closed cryptographic loop with no real IdP. In
tests, `TestTokens.cs` resolves this singleton from `WebApplicationFactory.Services` to mint stand-in
subject/actor tokens — that's why the singleton lifetime matters. Production replaces this with AWS KMS.

## Invariants to preserve (deliberate design choices, not omissions)

- **`audience` is required** even though RFC 8693 makes it optional — refusing to mint an unrestricted token
  is the primary confused-deputy guard.
- **Always downscope to the intersection**; never honor requested scope directly.
- **`auth_version` is the revocation epoch.** Minted tokens carry it; a subject token whose version is behind
  the store's current version is rejected (`invalid_grant`). This models revocation without re-auth.
- **The minted token carries the RFC 8693 `act` claim** (`act.sub` = actor) for audit attribution. Don't drop it.
- Rely on the framework for all crypto/token handling; custom code belongs only in the business-authorization
  logic (downscoping, actor-trust, epoch). If you find yourself writing crypto, stop.

## Testing

Tests are end-to-end over the real pipeline via `WebApplicationFactory<Program>` (`Program.cs` ends with
`public partial class Program;` to enable this). xUnit constructs a fresh test-class instance per test, so each
gets a fresh singleton `InMemoryPermissionStore` — the revocation test can mutate state without leaking. The
happy-path tests validate the minted token **cryptographically** (signature + `aud`) and assert its claims,
rather than trusting the response body.
