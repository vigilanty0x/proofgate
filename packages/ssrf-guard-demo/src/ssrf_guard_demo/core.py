"""URL validation that binds allowed decisions to resolved global addresses."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit

MAX_URL_BYTES = 8_192
MAX_ADDRESSES = 32
LOCAL_SUFFIXES = ("localhost", ".localhost", ".local", ".internal", ".home", ".lan")


def _canonical_host(host):
    if not isinstance(host, str) or not host:
        raise ValueError("host is required")
    host = host.rstrip(".").casefold()
    if not host or "%" in host:
        raise ValueError("invalid host")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid IDNA host") from exc


def _default_resolver(host, port):
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _resolved_values(answers):
    if not isinstance(answers, (list, tuple)) or not 1 <= len(answers) <= MAX_ADDRESSES:
        raise ValueError("resolver returned no bounded answer set")
    values = []
    for answer in answers:
        value = answer
        if isinstance(answer, tuple) and len(answer) >= 5 and isinstance(answer[4], tuple):
            value = answer[4][0]
        if not isinstance(value, str):
            raise ValueError("resolver answer is not an IP string")
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            raise PermissionError("ipv4_mapped")
        if not address.is_global:
            raise PermissionError("non_global_ip")
        values.append(str(address))
    return sorted(set(values))


def guard(url, *, allowed_hosts=(), resolver=None):
    if not isinstance(url, str) or not url or len(url.encode("utf-8")) > MAX_URL_BYTES:
        return {"decision": "blocked", "reason": "parse"}
    try:
        parts = urlsplit(url)
    except ValueError:
        return {"decision": "blocked", "reason": "parse"}
    if parts.scheme.casefold() not in {"http", "https"}:
        return {"decision": "blocked", "reason": "scheme"}
    if not parts.hostname or parts.username is not None or parts.password is not None:
        return {"decision": "blocked", "reason": "authority"}
    try:
        port = parts.port or (443 if parts.scheme.casefold() == "https" else 80)
    except ValueError:
        return {"decision": "blocked", "reason": "port"}
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        return {"decision": "blocked", "reason": "port"}
    try:
        host = _canonical_host(parts.hostname)
    except ValueError:
        return {"decision": "blocked", "reason": "authority"}
    if host == "localhost" or any(host.endswith(suffix) for suffix in LOCAL_SUFFIXES):
        return {"decision": "blocked", "reason": "local_name"}
    if allowed_hosts:
        if not isinstance(allowed_hosts, (list, tuple)) or len(allowed_hosts) > 1_000:
            return {"decision": "blocked", "reason": "allowlist"}
        try:
            allowed = {_canonical_host(item) for item in allowed_hosts}
        except (TypeError, ValueError):
            return {"decision": "blocked", "reason": "allowlist"}
        if host not in allowed:
            return {"decision": "blocked", "reason": "allowlist"}
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is None and re.fullmatch(r"(?i)(?:0x[0-9a-f]+|[0-9.]+)", host):
        return {"decision": "blocked", "reason": "numeric_host"}
    try:
        answers = [str(literal)] if literal is not None else (resolver or _default_resolver)(host, port)
        addresses = _resolved_values(answers)
    except PermissionError as exc:
        return {"decision": "blocked", "reason": str(exc)}
    except (OSError, TypeError, ValueError):
        return {"decision": "blocked", "reason": "resolution"}
    return {
        "decision": "allowed",
        "host": host,
        "scheme": parts.scheme.casefold(),
        "port": port,
        "resolved_addresses": addresses,
        "binding": {"host": host, "port": port, "addresses": addresses},
    }


def run(data):
    if not isinstance(data, dict) or "url" not in data or set(data) - {"url", "allowed_hosts"}:
        raise ValueError("input must contain url and optional allowed_hosts")
    return guard(**data)
