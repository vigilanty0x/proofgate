from __future__ import annotations
from dataclasses import dataclass
from typing import Any

_ALLOWED_TYPES={"any","array","boolean","integer","null","number","object","string"}

@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    compatible: bool
    breaking: tuple[str,...]
    notes: tuple[str,...]
    def as_dict(self):
        return {"compatible":self.compatible,"breaking":list(self.breaking),"notes":list(self.notes)}

def _normalize(schema: Any):
    if not isinstance(schema,dict) or schema.get("type")!="object":
        raise ValueError("only object schemas are supported")
    properties=schema.get("properties",{})
    required=schema.get("required",[])
    if not isinstance(properties,dict):
        raise ValueError("properties must be an object")
    if not isinstance(required,list) or any(not isinstance(v,str) for v in required):
        raise ValueError("required must be an array of strings")
    if len(required)!=len(set(required)):
        raise ValueError("required contains duplicates")
    normalized={}
    for name,spec in properties.items():
        if not isinstance(name,str) or not name or not isinstance(spec,dict):
            raise ValueError("invalid property")
        field_type=spec.get("type","any")
        if field_type not in _ALLOWED_TYPES:
            raise ValueError(f"unsupported type for {name}: {field_type}")
        normalized[name]=field_type
    unknown=set(required)-set(normalized)
    if unknown:
        raise ValueError("required references unknown properties")
    return normalized,set(required)

def compare_schemas(old: Any,new: Any)->CompatibilityReport:
    old_props,old_req=_normalize(old)
    new_props,new_req=_normalize(new)
    breaking=[]; notes=[]
    for name,old_type in sorted(old_props.items()):
        if name not in new_props:
            breaking.append(f"removed_property:{name}"); continue
        if new_props[name]!=old_type:
            breaking.append(f"type_changed:{name}:{old_type}->{new_props[name]}")
        if name not in old_req and name in new_req:
            breaking.append(f"optional_became_required:{name}")
        elif name in old_req and name not in new_req:
            notes.append(f"required_became_optional:{name}")
    for name in sorted(set(new_props)-set(old_props)):
        (breaking if name in new_req else notes).append(
            f"{'new_required_property' if name in new_req else 'new_optional_property'}:{name}"
        )
    return CompatibilityReport(not breaking,tuple(breaking),tuple(notes))
