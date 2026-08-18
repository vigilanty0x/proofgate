TYPES={"object":dict,"array":list,"string":str,"integer":int,"number":(int,float),"boolean":bool,"null":type(None)}
def validate(value,schema,path="$"):
    errors=[]
    expected=schema.get("type")
    if expected not in TYPES: return [{"path":path,"error":"unknown_type"}]
    if not isinstance(value,TYPES[expected]) or expected=="integer" and isinstance(value,bool): return [{"path":path,"error":"type"}]
    if expected=="object":
        required=schema.get("required",[])
        for key in required:
            if key not in value: errors.append({"path":path+"."+key,"error":"required"})
        props=schema.get("properties",{})
        if schema.get("additionalProperties",True) is False:
            for key in value.keys()-props.keys(): errors.append({"path":path+"."+key,"error":"additional"})
        for key in value.keys()&props.keys(): errors+=validate(value[key],props[key],path+"."+key)
    if expected=="array":
        if len(value)>schema.get("maxItems",1000): errors.append({"path":path,"error":"maxItems"})
        for i,item in enumerate(value): errors+=validate(item,schema["items"],f"{path}[{i}]")
    return errors
def run(data):
    errors=validate(**data); return {"valid":not errors,"errors":errors}

