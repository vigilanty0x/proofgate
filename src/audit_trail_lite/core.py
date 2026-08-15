import hashlib,json
def append(events,actor,action,target,metadata=None):
 if len(events)>=100000: raise ValueError("event limit")
 identity={"index":len(events),"previous":events[-1]["hash"] if events else "0"*64,"actor":actor,"action":action,"target":target,"metadata":metadata or {}}
 return [*events,{**identity,"hash":hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(",",":")).encode()).hexdigest()}]
def verify(events):
 rebuilt=[]
 for e in events:
  rebuilt=append(rebuilt,e["actor"],e["action"],e["target"],e["metadata"])
  if rebuilt[-1]!=e: return {"valid":False,"index":e.get("index")}
 return {"valid":True,"count":len(events)}
def query(events,actor=None,action=None): return [e for e in events if (actor is None or e["actor"]==actor) and (action is None or e["action"]==action)]
def run(data):
 events=[]
 for item in data["events"]: events=append(events,**item)
 return {"events":events,"verification":verify(events)}

