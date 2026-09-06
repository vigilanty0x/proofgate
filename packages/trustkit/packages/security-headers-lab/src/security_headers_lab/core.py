"""Strict offline evaluation of HTTP response security headers."""

import re

REQUIRED = {"content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy"}
RESTRICTIVE_REFERRER_POLICIES = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
SENSITIVE_PERMISSIONS = {"camera", "microphone", "geolocation"}
MIN_HSTS_MAX_AGE = 31_536_000
MAX_HEADERS = 200


def _issue(issues, header, issue):
    item = {"header": header, "issue": issue}
    if item not in issues:
        issues.append(item)


def evaluate(headers, *, https=True, minimum_hsts_max_age=MIN_HSTS_MAX_AGE):
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        raise ValueError("headers must be a bounded object")
    if not isinstance(https, bool):
        raise ValueError("https must be a boolean")
    if isinstance(minimum_hsts_max_age, bool) or not isinstance(minimum_hsts_max_age, int) or minimum_hsts_max_age <= 0:
        raise ValueError("minimum_hsts_max_age must be a positive integer")
    normalized = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key or len(key) > 256 or len(value) > 16_384:
            raise ValueError("header names and values must be bounded strings")
        folded = key.casefold()
        if folded in normalized:
            raise ValueError("duplicate case-insensitive header")
        normalized[folded] = value.strip()
    issues = []
    for key in REQUIRED:
        if not normalized.get(key):
            _issue(issues, key, "missing")
    if normalized.get("x-content-type-options", "").casefold() != "nosniff":
        _issue(issues, "x-content-type-options", "value")

    if https:
        hsts = normalized.get("strict-transport-security", "")
        if not hsts:
            _issue(issues, "strict-transport-security", "missing")
        else:
            matches = re.findall(r"(?i)(?:^|;)\s*max-age\s*=\s*([^;\s]+)", hsts)
            if len(matches) != 1 or not matches[0].isdigit() or int(matches[0]) < minimum_hsts_max_age:
                _issue(issues, "strict-transport-security", "max_age")

    csp = normalized.get("content-security-policy", "")
    directives = {}
    for part in csp.split(";"):
        tokens = part.strip().casefold().split()
        if tokens:
            if tokens[0] in directives:
                _issue(issues, "content-security-policy", "duplicate_directive")
            directives[tokens[0]] = tokens[1:]
    script_sources = directives.get("script-src", directives.get("default-src", []))
    if not script_sources:
        _issue(issues, "content-security-policy", "script_policy")
    unsafe_tokens = {"*", "'unsafe-inline'", "'unsafe-eval'", "data:", "blob:", "filesystem:", "javascript:", "http:"}
    if any(token in unsafe_tokens or "*" in token or token.startswith(("http:", "data:", "blob:", "filesystem:", "javascript:")) for token in script_sources):
        _issue(issues, "content-security-policy", "unsafe_script_source")

    referrer = normalized.get("referrer-policy", "").casefold()
    policies = [part.strip() for part in referrer.split(",") if part.strip()]
    if not policies or any(policy not in RESTRICTIVE_REFERRER_POLICIES for policy in policies):
        _issue(issues, "referrer-policy", "value")

    permissions = normalized.get("permissions-policy", "")
    parsed_permissions = {}
    for directive in permissions.split(","):
        match = re.fullmatch(r"\s*([A-Za-z0-9-]+)\s*=\s*(\([^)]*\)|\*)\s*", directive)
        if match:
            parsed_permissions[match.group(1).casefold()] = match.group(2).replace(" ", "")
        elif directive.strip():
            _issue(issues, "permissions-policy", "syntax")
    if any(parsed_permissions.get(feature) != "()" for feature in SENSITIVE_PERMISSIONS):
        _issue(issues, "permissions-policy", "sensitive_features")
    return {"status": "hardened" if not issues else "blocked", "issues": issues}


def run(data):
    if not isinstance(data, dict) or "headers" not in data or set(data) - {"headers", "https", "minimum_hsts_max_age"}:
        raise ValueError("input must contain headers and only supported policy options")
    return evaluate(**data)
