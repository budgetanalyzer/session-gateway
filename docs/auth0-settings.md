# Recommended Auth0 Settings

These settings align Auth0 with Session Gateway's current runtime defaults:

- `SESSION_TTL_SECONDS=900`
- `SESSION_REFRESH_THRESHOLD_SECONDS=300`
- frontend heartbeat cadence `VITE_HEARTBEAT_INTERVAL_MS=120000` (2 minutes)
- OAuth2 authorization code flow with PKCE

## API Configuration

In Auth0, open `Applications > APIs > budget-analyzer-api`.

- **Identifier**: match `IDP_AUDIENCE`
  For this repository, the default value is `https://api.budgetanalyzer.org`.
- **Maximum Access Token Lifetime**: `900` seconds
- **Implicit / Hybrid Flow Lifetime**: not relevant for Session Gateway

Session Gateway requests the API audience during browser login, so the API access-token lifetime
controls the access token used by the browser authorization-code flow. Session Gateway does not use
implicit or hybrid login.

## Application Configuration

In Auth0, open `Applications > [browser app] > Settings`.

- **Refresh Token Rotation**: enabled
- **Refresh Token Reuse Interval / Overlap**: `0`
- **Idle Refresh Token Lifetime**: `3600` seconds
- **Maximum Refresh Token Lifetime**: `28800` seconds
- **ID Token Expiration**: `3600` seconds

The refresh-token settings matter more than the ID-token setting. Session Gateway stores the
refresh token server-side and uses it during `GET /auth/v1/session` to validate the IdP grant and
refresh access tokens near expiry.

## Tenant Session Configuration

In Auth0, open `Settings > Advanced > Session Expiration`.

- **Default Session Policy**: non-persistent
- **Idle Session Lifetime**: `15` minutes
- **Maximum Session Lifetime**: `480` minutes

These values keep the Auth0 SSO session closer to the app session model. If the Redis session
expires and the user goes back through login, they should not keep getting silently reauthenticated
for days from a long-lived Auth0 session.

Non-persistent helps here, but it is not a guarantee that every browser will drop the session on
close in every restore scenario. Explicit logout still matters.

### Why session policy matters for a financial application

With "Persistent" and a 3-day idle timeout, the app's 15-minute session expiration gives a false
sense of security:

1. User's app session expires (15 min idle, Redis key gone)
2. User clicks Login
3. Auth0 still has a live session (3-day idle, persistent cookie survived browser close)
4. Auth0 silently re-authenticates — no password prompt
5. User gets a new app session without proving they know the password

Someone who walks away from an unlocked browser gets back in without credentials as long as the
Auth0 session is alive. Setting the policy to non-persistent with a 15-minute idle timeout closes
this gap. The `/v2/logout` call in Session Gateway's `LogoutController` already kills the Auth0
session on explicit logout — these settings are the safety net for when logout doesn't happen
cleanly (browser crash, tab close, session timeout).

## Why These Values

- With a `900` second Auth0 access token and a `300` second refresh threshold, Session Gateway
  refreshes on the first heartbeat at or below the 5-minute remaining window.
- With the current 2-minute heartbeat cadence, active browser sessions typically refresh around 10
  minutes after login or the previous refresh.
- That makes IdP-grant revocation checks meaningful during active use without forcing a refresh on
  every heartbeat.
- If the Auth0 API access token remains at `86400` seconds, the refresh path rarely runs before the
  15-minute Redis session expires, so revocation detection through refresh is effectively delayed.

## Scope Notes

- These recommendations apply to the browser OAuth2 flow and to native clients that request Auth0
  access tokens for the same API audience.
- Session Gateway sessions created through `POST /auth/token/exchange` still use the local
  `SESSION_TTL_SECONDS` value for the opaque session lifetime.
- Token-exchange sessions do not store an Auth0 refresh token, so they do not participate in the
  browser heartbeat refresh path.
