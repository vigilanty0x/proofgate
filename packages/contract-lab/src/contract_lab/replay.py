from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .canonical import canonical_digest

@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    contract_digest: str
    request_digest: str
    response_digest: str
    def as_dict(self):
        return {"contract_digest":self.contract_digest,"request_digest":self.request_digest,"response_digest":self.response_digest}

def build_receipt(*,contract:Any,request:Any,response:Any)->ReplayReceipt:
    return ReplayReceipt(canonical_digest(contract),canonical_digest(request),canonical_digest(response))

def verify_receipt(receipt:ReplayReceipt,*,contract:Any,request:Any,response:Any)->bool:
    return receipt==build_receipt(contract=contract,request=request,response=response)
