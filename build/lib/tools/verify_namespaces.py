#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""antinel verify-namespaces (P-A3, 0.17.0) - namespace-list verification aid.

Python's standard library has NO ed25519, and this package promises stdlib-only.
So this tool does NOT verify the signature itself; it removes every OTHER way
for a third party to get stuck:

  1. prints the sha256 of the CANONICAL bytes the signature covers
     (json.dumps(doc-minus-signature, ensure_ascii=False, sort_keys=True,
      separators=(",",":")) -- byte-identical to what r1v3/make_namespaces.py
     signed), so nobody has to re-derive the normalization;
  2. checks that signature.public_key_fingerprint equals the fingerprint pinned
     in README.md (a swapped key is caught here, stdlib-only);
  3. prints a ready-to-paste OpenSSL command for the one step that needs a real
     ed25519 implementation.

Exit codes: 0 = list readable + fingerprint matches README; 1 = fingerprint
mismatch or missing signature block; 2 = file unreadable.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
LIST = PKG / "antinel-namespaces.json"
README = PKG / "README.md"


def canonical(doc):
    payload = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Antinel namespace-list verification aid")
    ap.add_argument("--list", default=str(LIST))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        doc = json.loads(Path(a.list).read_text(encoding="utf-8"))
    except Exception as e:
        out = {"status": "error", "reason": "namespaces list unreadable: %s" % e}
        print(json.dumps(out) if a.json else out["reason"])
        return 2
    sig = doc.get("signature") or {}
    canon = canonical(doc).encode("utf-8")
    canon_sha = "sha256:" + hashlib.sha256(canon).hexdigest()
    pinned = None
    try:
        m = re.search(r"sha256:[0-9a-f]{16}", README.read_text(encoding="utf-8"))
        pinned = m.group(0) if m else None
    except Exception:
        pass
    fp_ok = bool(sig.get("public_key_fingerprint")) and sig.get("public_key_fingerprint") == pinned
    out = {
        "status": "ok" if fp_ok else "fingerprint-mismatch",
        "canonical_sha256": canon_sha,
        "signature_fingerprint": sig.get("public_key_fingerprint"),
        "readme_pinned_fingerprint": pinned,
        "fingerprint_match": fp_ok,
        "namespaces": doc.get("namespaces"),
        "openssl_verify_command": (
            "python -c \"import json;doc=json.load(open(r'{list}',encoding='utf-8'));"
            "open(r'{pfile}','wb').write(bytes.fromhex(doc['signature']['public_key']));"
            "open(r'{sfile}','wb').write(bytes.fromhex(doc['signature']['value']));"
            "open(r'{cfile}','wb').write(json.dumps({{k:v for k,v in doc.items() if k!='signature'}},"
            " ensure_ascii=False, sort_keys=True, separators=(',',':')).encode('utf-8'))\" && "
            "openssl pkeyutl -verify -pubin -inkey {pfile} -rawin -in {cfile} -sigfile {sfile}"
        ).format(list=a.list, pfile="ns_pub.key", sfile="ns_sig.bin", cfile="ns_canon.bin"),
        "note": "canonical form: json.dumps(doc-minus-signature, ensure_ascii=False, "
                "sort_keys=True, separators=(',',':')) -- byte-identical to what the "
                "builder signed",
    }
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        print("[{}] fingerprint {} (README pinned: {})".format(
            "OK" if fp_ok else "MISMATCH", out["signature_fingerprint"], pinned))
        print("canonical bytes sha256:", canon_sha)
        print("verify signature (needs openssl):")
        print(" ", out["openssl_verify_command"])
    return 0 if fp_ok else 1


if __name__ == "__main__":
    sys.exit(main())
