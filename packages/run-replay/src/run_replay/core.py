import hashlib,json
def replay(events):
    if len(events)>100000: raise ValueError("event limit")
    state={}
    for event in events:
        op,key=event["op"],event["key"]
        if op=="set": state[key]=event["value"]
        elif op=="increment":
            if not isinstance(state.get(key,0),(int,float)): raise ValueError("non numeric increment")
            state[key]=state.get(key,0)+event["value"]
        elif op=="append":
            if key not in state: state[key]=[]
            if not isinstance(state[key],list): raise ValueError("non list append")
            state[key]=[*state[key],event["value"]]
        else: raise ValueError("unknown operation")
    canonical=json.dumps(state,sort_keys=True,separators=(",",":"))
    return {"state":state,"events":len(events),"sha256":hashlib.sha256(canonical.encode()).hexdigest()}
def run(data): return replay(**data)

