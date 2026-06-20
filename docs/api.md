# API Documentation

## `GET /health`

Returns `ok`.

## `GET /dashboard`

Returns the HTML dashboard.

## `GET /api/metrics`

Returns dashboard statistics in JSON.

### Response Fields

- `total_requests`
- `allowed_requests`
- `blocked_requests`
- `total_events`
- `top_attack_types`
- `top_offending_ips`
- `recent_alerts`

## Proxy Routes

All other methods and paths are forwarded to the configured upstream application when not blocked.
