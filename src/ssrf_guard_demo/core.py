import ipaddress
from urllib.parse import urlsplit
def guard(url,*,allowed_hosts=()):
 try: parts=urlsplit(url)
 except ValueError: return {"decision":"blocked","reason":"parse"}
 if parts.scheme not in {"http","https"}: return {"decision":"blocked","reason":"scheme"}
 if not parts.hostname or parts.username or parts.password: return {"decision":"blocked","reason":"authority"}
 host=parts.hostname.casefold()
 if allowed_hosts and host not in {x.casefold() for x in allowed_hosts}: return {"decision":"blocked","reason":"allowlist"}
 try:
  ip=ipaddress.ip_address(host)
  if not ip.is_global: return {"decision":"blocked","reason":"non_global_ip"}
 except ValueError:
  if host=="localhost" or host.endswith(".local"): return {"decision":"blocked","reason":"local_name"}
 return {"decision":"allowed","host":host,"scheme":parts.scheme}
def run(data): return guard(**data)

