# QuickStack Auth Proxy

QuickStack Auth Proxy is a small Go reverse proxy that protects certain [QuickStack](https://github.com/biersoeckli/QuickStack) services with a signed, one-time access token.

It is intended to sit behind an ingress or forward-auth setup. A client first
opens a sandbox URL containing `?token=<JWT>`. The proxy validates that token,
stores the authenticated sandbox identity in a secure session cookie, removes
the token from the URL, and redirects the client back to the same page. Later
requests use the session cookie and are proxied to the sandbox service in the
Kubernetes cluster.

The proxy routes regular application traffic to the required `port` claim in
the access token. Paths beginning with `/files` always use port `80`, regardless
of that claim, on:

```
<claimId>.<namespace>.svc.cluster.local
```

## Authentication behavior

Access tokens must be HS256 JWTs signed with `AGENT_JWT_SECRET`. They must use
the issuer `QuickStack-auth-proxy`, have a unique JWT ID (`jti`), an expiry
(`exp`), and the following claims:

| Claim | Purpose |
| --- | --- |
| `agentId` | Agent identifier |
| `claimId` | Sandbox service name |
| `namespace` | Kubernetes namespace containing the sandbox |
| `port` | **Required.** Target port for all routes except `/files`; must be from 1 through 65535. |
| `type` | Optional for the browser flow. Must be `api` for direct bearer-token API/WebSocket access. |

This is a breaking change: the QuickStack component that issues access tokens
must include the numeric `port` claim. Access tokens (and existing session
cookies) without a valid port are rejected.

## API and WebSocket bearer tokens

In addition to the browser flow, the proxy accepts reusable access tokens
carried as `Authorization: Bearer <JWT>` when the token has the custom claim
`"type": "api"`. Such requests are routed directly to the sandbox target; there
is **no** token-to-session exchange, no redirect, and no session cookie.

- API tokens are **reusable** and not tracked for replay; they are only bounded
  by their `exp` claim. Because they do not rely on process-local state, they
  also work across multiple replicas.
- `type` must be exactly `api`; missing/other values are rejected with `401`.
- `type: "api"` tokens are rejected by the browser `?token=` exchange, and
  browser access tokens (no/other `type`) are rejected as bearer tokens.
- The `port` claim is always used, including for `/files` paths, so API tokens
  can never be routed to the `/files` port (`80`).
- The `Authorization` header is stripped before proxying. `Origin` and
  `Referer` are preserved for API/WebSocket requests (and stripped for the
  browser flow) so the target can apply its own checks.
- WebSocket upgrades are proxied transparently; the bearer token is validated
  during the handshake.

The `Authorization` header must reach the proxy; if forward-auth is configured,
make sure the ingress forwards it.

Each access token can be exchanged only once while this proxy process is
running. Replay tracking and session-signing keys are held in memory, so use a
single replica unless you add shared storage and a shared session secret. A
restart invalidates existing sessions and resets access-token replay tracking.

The session cookie is `HttpOnly`, `Secure`, and `SameSite=None`; deploy it
behind HTTPS. The proxy removes its own session cookie, the `Authorization`,
`X-Forwarded-Uri`, `Origin`, and `Referer` headers before proxying requests.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `AGENT_JWT_SECRET` | _none_ | **Required in production.** Shared secret used to verify incoming HS256 access tokens. Keep it in a secret manager or Kubernetes Secret. Requests with access tokens fail if it is unset. |
| `PORT` | `3000` | TCP port on which the proxy listens. |
| `AGENT_SESSION_JWT_TTL_SECONDS` | `3600` | Lifetime, in seconds, for the session JWT stored in the cookie. Invalid or non-numeric values fall back to `3600`. |
| `AUTH_PROXY_DEBUG_ENABLED` | `false` | Set to exactly `true` to return and log a redacted JSON diagnostic when a request containing an invalid access token is rejected. Successful token redirects additionally log the internal target host and port. This exposes cluster topology; do not enable in normal production operation. |
| `AGENT_ACCESS_TOKEN_TTL_SECONDS` | `60` | Reported by debug diagnostics. It does **not** currently change access-token validation or issuance; token expiry is determined by the access token's `exp` claim. Invalid, empty, or non-positive values are reported as `60`. |
