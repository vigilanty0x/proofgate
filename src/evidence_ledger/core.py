import hashlib,json
def append(chain,payload):
    if len(chain)>100000: raise ValueError("ledger limit")
    previous=chain[-1]["hash"] if chain else "0"*64
    index=len(chain); identity={"index":index,"previous":previous,"payload":payload}
    record={**identity,"hash":hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
    return [*chain,record]
def verify(chain):
    rebuilt=[]
    for record in chain:
        rebuilt=append(rebuilt,record["payload"])
        if rebuilt[-1]!=record: return {"valid":False,"index":record.get("index")}
    return {"valid":True,"records":len(chain),"head":chain[-1]["hash"] if chain else "0"*64}
def run(data):
    chain=[]
    for payload in data["payloads"]: chain=append(chain,payload)
    return {"chain":chain,"verification":verify(chain)}

