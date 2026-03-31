# Session Configuration

## Shared Session Contract

Session Gateway and ext_authz must stay aligned on three things:

- `SESSION_KEY_PREFIX`, default `session:`
- `SESSION_COOKIE_NAME`, default `BA_SESSION`
- the Redis session hash field `expires_at`, written by Session Gateway and enforced by ext_authz

Changing either shared value is a cross-repo contract change. Existing live sessions are keyed by
the current prefix and browsers hold the current cookie name.

## Session Gateway Source Of Truth

Session settings are bound through `SessionProperties` and defaulted in
`src/main/resources/application.yml`.

Defaults:

- `SESSION_KEY_PREFIX=session:`
- `SESSION_TTL_SECONDS=900`
- `SESSION_REFRESH_THRESHOLD_SECONDS=600`
- `SESSION_OAUTH2_STATE_TTL_SECONDS=900`
- `SESSION_COOKIE_NAME=BA_SESSION`
- `SESSION_COOKIE_DOMAIN_OVERRIDE` unset
- `SESSION_COOKIE_SECURE=true`
- `SESSION_COOKIE_SAME_SITE=Strict`

`SESSION_COOKIE_DOMAIN_OVERRIDE` is wired in `src/main/resources/application.yml` with a blank
default so the public cookie remains host-only unless an explicit override is configured.

Startup validation rejects:

- blank `session.key-prefix`
- blank `session.cookie.name`
- `session.refresh-threshold-seconds >= session.ttl-seconds`
- unsupported `session.cookie.same-site` values

Startup does not enforce an allowlist of cookie names beyond the non-blank requirement. Changing
`SESSION_COOKIE_NAME` still changes a cross-repo cookie contract and must stay aligned with
ext_authz.

After startup completes, Session Gateway logs the configured public cookie name and whether a
domain override is enabled.

## Cookie Behavior

The public browser session contract is `BA_SESSION` by default. Session Gateway reads, sets, and
clears that cookie exclusively through `SessionCookieHelper`. ext_authz must look up that same
configured public cookie name.

An internal framework cookie named `SESSION` may still appear during Spring-managed flows. That is
not the browser auth contract. Session Gateway does not read, refresh, or clear that framework
cookie when managing authenticated browser sessions.

Default public-cookie behavior is host-only. Session Gateway does not emit a `Domain` attribute
unless `SESSION_COOKIE_DOMAIN_OVERRIDE` is set.

Use `SESSION_COOKIE_DOMAIN_OVERRIDE` only as an ingress workaround when a parent-domain cookie is
required. It is not the primary path.

Heartbeat and logout clearing behavior follows the same public-cookie rule:

- no override configured: clear a host-only cookie
- override configured: clear a cookie with that explicit `Domain` attribute

If the browser presents a cookie for a missing or expired Redis session, `GET /auth/session`
returns `401` and clears the stale cookie.

## OAuth2 State TTL

`SESSION_OAUTH2_STATE_TTL_SECONDS` applies only to `oauth2:state:*` keys used during the OAuth2
round-trip. It is separate from the browser session TTL and should remain long enough for MFA,
account selection, and slow IdP handoffs.
