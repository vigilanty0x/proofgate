# Contract Lab shared model

The root core intentionally supports a bounded portable layer: canonical JSON/digests, a conservative object-schema compatibility subset, replay receipts, and HMAC-SHA256 webhook proof primitives. It starts no network server, fetches no URL, executes no webhook, and does not claim full JSON Schema support.

Schema evolution is fail-closed: removing a property, changing its type, optional->required, or adding a required property is breaking. Required->optional and new optional fields are compatible notes. Malformed/unsupported schemas are BLOCKED.

Canonical serialization is UTF-8 JSON with sorted keys, compact separators, and NaN/Infinity rejected. Replay receipts bind contract/request/response digests. Webhook verification operates on exact payload bytes with constant-time comparison.
