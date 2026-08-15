import re
def parse(text):
 result={}
 for n,line in enumerate(text.splitlines(),1):
  line=line.strip()
  if not line or line.startswith("#"): continue
  if "=" not in line: raise ValueError(f"invalid line {n}")
  key,value=line.split("=",1)
  if not re.fullmatch(r"[A-Z][A-Z0-9_]*",key): raise ValueError(f"invalid key {key}")
  if key in result: raise ValueError("duplicate key")
  result[key]=value
 return result
def check(actual_keys,example_text,secret_keys=()):
 example=parse(example_text); actual=set(actual_keys); keys=set(example)
 leaked=sorted(k for k in secret_keys if example.get(k))
 return {"status":"verified" if actual==keys and not leaked else "blocked","missing":sorted(actual-keys),"extra":sorted(keys-actual),"leaked":leaked}
def run(data): return check(**data)

