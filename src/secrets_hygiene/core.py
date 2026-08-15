import re
PATTERNS={"private_key":re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),"github_token":re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),"assignment":re.compile(r"(?i)(api[_-]?key|password|secret)\s*=\s*[^\s]{8,}")}
def scan(files):
 findings=[]
 for path,text in files.items():
  if len(text)>2_000_000: findings.append({"path":path,"kind":"size_blocked","line":None}); continue
  for number,line in enumerate(text.splitlines(),1):
   for kind,pattern in PATTERNS.items():
    if pattern.search(line): findings.append({"path":path,"kind":kind,"line":number})
 return {"status":"clean" if not findings else "blocked","findings":findings}
def run(data): return scan(**data)

