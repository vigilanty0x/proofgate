REQUIRED={"content-security-policy","x-content-type-options","referrer-policy","permissions-policy"}
def evaluate(headers,*,https=True):
 normalized={k.casefold():v for k,v in headers.items()}; issues=[]
 for key in REQUIRED:
  if not normalized.get(key): issues.append({"header":key,"issue":"missing"})
 if normalized.get("x-content-type-options","").casefold()!="nosniff": issues.append({"header":"x-content-type-options","issue":"value"})
 if https and not normalized.get("strict-transport-security"): issues.append({"header":"strict-transport-security","issue":"missing"})
 if "unsafe-inline" in normalized.get("content-security-policy",""): issues.append({"header":"content-security-policy","issue":"unsafe_inline"})
 return {"status":"hardened" if not issues else "blocked","issues":issues}
def run(data): return evaluate(**data)

