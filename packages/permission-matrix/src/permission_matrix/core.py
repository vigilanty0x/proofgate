"""Strict deny-by-default permission matrix evaluation."""

MAX_AXIS = 1_000
MAX_RULES = 10_000
MAX_CELLS = 100_000


def _name(value, label, wildcard=False):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256 or (value == "*" and not wildcard):
        raise ValueError(f"{label} must be a bounded nonempty string")
    return value


def _validate(assignments, rules):
    if not isinstance(assignments, dict) or len(assignments) > MAX_AXIS:
        raise ValueError("assignments must be a bounded object")
    for subject, roles in assignments.items():
        _name(subject, "subject")
        if not isinstance(roles, list) or len(roles) > MAX_AXIS or len(roles) != len(set(roles)):
            raise ValueError("assigned roles must be a bounded unique list")
        for role in roles:
            _name(role, "role")
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("rules must be a bounded list")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"role", "action", "resource", "effect"}:
            raise ValueError("each rule must have an exact shape")
        _name(rule["role"], "role")
        _name(rule["action"], "action", wildcard=True)
        _name(rule["resource"], "resource", wildcard=True)
        if rule["effect"] not in {"allow", "deny"}:
            raise ValueError("rule effect must be allow or deny")


def decide(subject, action, resource, assignments, rules):
    _name(subject, "subject")
    _name(action, "action")
    _name(resource, "resource")
    _validate(assignments, rules)
    roles = set(assignments.get(subject, ()))
    matched = [rule for rule in rules if rule["role"] in roles and rule["action"] in {action, "*"} and rule["resource"] in {resource, "*"}]
    if any(rule["effect"] == "deny" for rule in matched):
        return {"decision": "denied", "reason": "explicit_deny"}
    if any(rule["effect"] == "allow" for rule in matched):
        return {"decision": "allowed", "reason": "explicit_allow"}
    return {"decision": "denied", "reason": "no_rule"}


def _axis(values, label):
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_AXIS or len(values) != len(set(values)):
        raise ValueError(f"{label} must be a bounded unique nonempty list")
    for value in values:
        _name(value, label)
    return values


def matrix(subjects, actions, resources, assignments, rules):
    subjects = _axis(subjects, "subjects")
    actions = _axis(actions, "actions")
    resources = _axis(resources, "resources")
    _validate(assignments, rules)
    if len(subjects) * len(actions) * len(resources) > MAX_CELLS:
        raise ValueError("matrix limit exceeded")
    return [{"subject": subject, "action": action, "resource": resource, **decide(subject, action, resource, assignments, rules)} for subject in subjects for action in actions for resource in resources]


def run(data):
    if not isinstance(data, dict) or set(data) != {"subjects", "actions", "resources", "assignments", "rules"}:
        raise ValueError("input must contain the exact matrix fields")
    return {"matrix": matrix(**data)}
