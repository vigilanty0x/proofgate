from __future__ import annotations
import argparse,json
from pathlib import Path
from .canonical import canonical_digest, canonical_roundtrip
from .evolution import compare_schemas
from .replay import ReplayReceipt, build_receipt, verify_receipt

def _read(path): return json.loads(Path(path).read_text(encoding="utf-8"))
def _emit(value): print(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False))

def main(argv=None):
    parser=argparse.ArgumentParser(prog="contract-lab")
    sub=parser.add_subparsers(dest="command",required=True)
    p=sub.add_parser("roundtrip"); p.add_argument("input")
    p=sub.add_parser("evolve"); p.add_argument("old"); p.add_argument("new")
    p=sub.add_parser("replay"); p.add_argument("fixture")
    args=parser.parse_args(argv)
    try:
        if args.command=="roundtrip":
            value=canonical_roundtrip(_read(args.input))
            _emit({"status":"PASS","digest":canonical_digest(value),"value":value}); return 0
        if args.command=="evolve":
            report=compare_schemas(_read(args.old),_read(args.new))
            _emit({"status":"PASS" if report.compatible else "FAIL",**report.as_dict()})
            return 0 if report.compatible else 1
        fixture=_read(args.fixture)
        if not isinstance(fixture,dict) or any(k not in fixture for k in ("contract","request","response")):
            raise ValueError("invalid replay fixture")
        receipt=build_receipt(contract=fixture["contract"],request=fixture["request"],response=fixture["response"])
        supplied=fixture.get("receipt")
        if supplied is None:
            _emit({"status":"PASS","receipt":receipt.as_dict()}); return 0
        if not isinstance(supplied,dict): raise ValueError("receipt must be object")
        candidate=ReplayReceipt(str(supplied.get("contract_digest","")),str(supplied.get("request_digest","")),str(supplied.get("response_digest","")))
        valid=verify_receipt(candidate,contract=fixture["contract"],request=fixture["request"],response=fixture["response"])
        _emit({"status":"PASS" if valid else "FAIL","receipt_valid":valid})
        return 0 if valid else 1
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        _emit({"status":"BLOCKED","reason":f"invalid_input:{type(exc).__name__}"}); return 2
