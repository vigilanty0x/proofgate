from __future__ import annotations
import hashlib,hmac

def _secret_bytes(secret: bytes|str)->bytes:
    value=secret.encode() if isinstance(secret,str) else secret
    if not isinstance(value,bytes) or not value:
        raise ValueError("secret must be non-empty")
    return value

def sign_sha256(secret:bytes|str,payload:bytes)->str:
    if not isinstance(payload,bytes):
        raise TypeError("payload must be bytes")
    return "sha256="+hmac.new(_secret_bytes(secret),payload,hashlib.sha256).hexdigest()

def verify_sha256(secret:bytes|str,payload:bytes,signature:str)->bool:
    if not isinstance(signature,str) or not signature.startswith("sha256="):
        return False
    return hmac.compare_digest(sign_sha256(secret,payload),signature)
