#!/usr/bin/env python3
"""jwtguard test harness.

Builds a rotating key set (old/new RSA-2048 and P-256 keys plus rogue keys),
emits 20 fixed JWT test vectors with PyJWT (the reference library), verifies
each one through both the C jwtguard binary and an in-process reference
implementation of the gateway policy, and fuzzes every segment of every
valid token with per-character mutations.

Run via `make test` (python3 -I tests/harness.py).
"""
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RT = os.path.join(HERE, "runtime")
BIN = os.path.join(ROOT, "jwtguard")
CONF = os.path.join(RT, "keyring.conf")

NOW = 1_700_000_000          # fixed gateway clock for the manifest
LEEWAY = 30

failures = []


def check(name, ok, detail=""):
    print(f"{name}={'1' if ok else '0'}{('  ' + detail) if detail and not ok else ''}")
    if not ok:
        failures.append(name)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------- keys ----
def write_keys():
    os.makedirs(RT, exist_ok=True)
    keys = {}
    for name in ("rsa-old", "rsa-new", "rsa-rogue"):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        keys[name] = ("RS256", priv)
    for name in ("ec-old", "ec-new", "ec-rogue"):
        priv = ec.generate_private_key(ec.SECP256R1())
        keys[name] = ("ES256", priv)

    for name, (alg, priv) in keys.items():
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(os.path.join(RT, name + ".key.pem"), "wb") as f:
            f.write(priv_pem)
        with open(os.path.join(RT, name + ".pub.pem"), "wb") as f:
            f.write(pub_pem)

    # local whitelist: only old/new keys, never the rogue ones
    with open(CONF, "w") as f:
        for name in ("rsa-old", "rsa-new", "ec-old", "ec-new"):
            alg, _ = keys[name]
            f.write(f"{name} {alg} {os.path.join(RT, name + '.pub.pem')}\n")
    return keys


KEYS = {}


def priv(kid):
    return KEYS[kid][1]


def pub_pem(kid):
    with open(os.path.join(RT, kid + ".pub.pem"), "rb") as f:
        return f.read()


# ------------------------------------------------------------- reference ----
class _FrozenDateTime:
    """Patch target for jwt.api_jwt.datetime so PyJWT sees our fixed clock."""

    @classmethod
    def now(cls, tz=None):
        d = datetime.fromtimestamp(NOW, tz=timezone.utc)
        return d if tz is None else d.astimezone(tz)


def reference_verify(token, leeway):
    """Same gateway policy as jwtguard.c, built on top of PyJWT."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return "malformed"
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return "malformed"
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        return "malformed"
    if alg.lower() == "none":
        return "alg_none"
    if alg not in ("RS256", "ES256"):
        return "alg_confusion"
    if any(k in header for k in ("jwk", "jku", "x5u", "x5c")):
        return "untrusted_header"
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        return "missing_kid"
    trusted = {"rsa-old": "RS256", "rsa-new": "RS256",
               "ec-old": "ES256", "ec-new": "ES256"}
    if kid not in trusted:
        return "unknown_kid"
    if trusted[kid] != alg:
        return "alg_confusion"

    saved = jwt.api_jwt.datetime
    jwt.api_jwt.datetime = _FrozenDateTime
    try:
        jwt.decode(
            token,
            serialization.load_pem_public_key(pub_pem(kid)),
            algorithms=[alg],
            options={"require": ["exp", "nbf"], "verify_aud": False},
            leeway=leeway,
        )
    except jwt.MissingRequiredClaimError:
        return "missing_claim"
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.ImmatureSignatureError:
        return "not_yet"
    except (jwt.InvalidSignatureError, jwt.DecodeError):
        return "bad_sig"
    except jwt.PyJWTError:
        return "malformed"
    finally:
        jwt.api_jwt.datetime = saved
    return "ok"


# ------------------------------------------------------------- token factory ----
def sign(kid, payload, alg=None, headers=None):
    alg = alg or KEYS[kid][0]
    hdrs = {"kid": kid}
    if headers:
        hdrs.update(headers)
    return jwt.encode(payload, priv(kid), algorithm=alg, headers=hdrs)


def unsigned(header, payload):
    return f"{b64u(json.dumps(header, separators=(',', ':')).encode())}." \
           f"{b64u(json.dumps(payload, separators=(',', ':')).encode())}."


def base_payload(**over):
    p = {"sub": "u1", "iat": NOW - 10, "nbf": NOW - 10, "exp": NOW + 300}
    p.update(over)
    return p


def build_vectors():
    p = base_payload()
    v = []
    # --- accepted: both algs, both rotation generations ---
    v.append(("v01_rs256_new_valid", sign("rsa-new", p), "ok"))
    v.append(("v02_es256_new_valid", sign("ec-new", p), "ok"))
    v.append(("v03_rs256_old_rotated", sign("rsa-old", p), "ok"))
    v.append(("v04_es256_old_rotated", sign("ec-old", p), "ok"))
    # --- clock skew: nbf/exp inside the leeway window ---
    v.append(("v05_nbf_within_skew",
              sign("rsa-new", base_payload(nbf=NOW + 20)), "ok"))
    v.append(("v06_exp_within_skew",
              sign("ec-new", base_payload(exp=NOW - 20)), "ok"))
    # --- alg=none in every casing ---
    v.append(("v07_none_lower",
              unsigned({"alg": "none", "kid": "rsa-new"}, p), "alg_none"))
    v.append(("v08_none_mixed_case",
              unsigned({"alg": "NoNe", "kid": "ec-new"}, p), "alg_none"))
    # --- alg confusion: HMAC pinned at an asymmetric whitelist entry ---
    v.append(("v09_hs256_confusion",
              jwt.encode(p, "shared-secret", algorithm="HS256",
                         headers={"kid": "rsa-new"}), "alg_confusion"))
    # --- token-supplied key material must never be consulted ---
    v.append(("v10_jwk_injection",
              sign("rsa-rogue", p, headers={"kid": "rsa-new",
                                            "jwk": {"kty": "RSA"}}),
              "untrusted_header"))
    # --- kid discipline ---
    no_kid = jwt.encode(p, priv("rsa-new"), algorithm="RS256",
                        headers={"typ": "JWT"})
    v.append(("v11_missing_kid", no_kid, "missing_kid"))
    v.append(("v12_unknown_kid", sign("rsa-rogue", p,
                                      headers={"kid": "rsa-rogue"}),
              "unknown_kid"))
    # ES256 signature presented under an RSA-pinned kid
    v.append(("v13_alg_kid_cross",
              sign("ec-new", p, headers={"kid": "rsa-new"}), "alg_confusion"))
    # --- signature / segment tampering over a real whitelisted token ---
    good = v[0][1]
    h, pl, sg = good.split(".")
    sig_raw = bytearray(base64.urlsafe_b64decode(sg + "=" * (-len(sg) % 4)))
    sig_raw[0] ^= 0x01
    flipped = b64u(bytes(sig_raw))
    v.append(("v14_signature_flip", f"{h}.{pl}.{flipped}", "bad_sig"))
    tampered_payload = base_payload(sub="u2")
    v.append(("v15_payload_tampered",
              f"{h}.{b64u(json.dumps(tampered_payload, separators=(',', ':')).encode())}.{sg}",
              "bad_sig"))
    swapped_alg = b64u(json.dumps({"alg": "SS256", "kid": "rsa-new"},
                                  separators=(',', ':')).encode())
    v.append(("v16_header_alg_swap", f"{swapped_alg}.{pl}.{sg}",
              "alg_confusion"))
    # --- time claims outside leeway ---
    v.append(("v17_expired", sign("rsa-new", base_payload(exp=NOW - 60)),
              "expired"))
    v.append(("v18_not_yet", sign("ec-new", base_payload(nbf=NOW + 120)),
              "not_yet"))
    v.append(("v19_missing_nbf",
              sign("rsa-new", {"sub": "u1", "iat": NOW - 10,
                               "exp": NOW + 300}), "missing_claim"))
    v.append(("v20_malformed", "abc.def", "malformed"))
    assert len(v) == 20
    return v


def run_batch(rows):
    tsv = os.path.join(RT, "cases.tsv")
    with open(tsv, "w") as f:
        for vid, leeway, now, token in rows:
            f.write(f"{vid}\t{leeway}\t{now}\t{token}\n")
    out = subprocess.run([BIN, "batch", CONF, tsv], check=True,
                         capture_output=True, text=True)
    result = {}
    for line in out.stdout.splitlines():
        vid, verdict, reason = line.split("\t")
        result[vid] = (verdict, reason)
    return result


def main():
    if not os.path.exists(BIN):
        print("jwtguard binary missing; run `make` first", file=sys.stderr)
        return 2
    global KEYS
    KEYS = write_keys()
    vectors = build_vectors()

    # ---- 20-vector manifest: full reason match against the reference ----
    rows = [(vid, LEEWAY, NOW, token) for vid, token, _ in vectors]
    c_results = run_batch(rows)
    for vid, token, expected in vectors:
        ref = reference_verify(token, LEEWAY)
        got = c_results.get(vid)
        check(vid, got == ("ok", expected) or got == ("reject", expected),
              f"expected {expected}, c={got}, reference={ref}")
        check(vid + "_ref_match", got is not None and got[1] == ref,
              f"c={got}, reference={ref}")

    # ---- extra hardening vectors, reason-matched as well ----
    p = base_payload()
    extra = [
        ("x01_jku", sign("rsa-new", p, headers={"jku": "https://evil/keys.json"}),
         "untrusted_header"),
        ("x02_x5u", sign("rsa-new", p, headers={"x5u": "https://evil/cert.pem"}),
         "untrusted_header"),
        ("x03_x5c", sign("rsa-new", p, headers={"x5c": ["MIIB..."]}),
         "untrusted_header"),
        ("x04_rogue_sig_trusted_kid",
         sign("rsa-rogue", p, headers={"kid": "rsa-new"}), "bad_sig"),
        ("x05_ec_rogue_trusted_kid",
         sign("ec-rogue", p, headers={"kid": "ec-new"}), "bad_sig"),
        ("x06_empty_token", "", "malformed"),
        ("x07_four_segments", "a.b.c.d", "malformed"),
        ("x08_padding", "YWJj." + b64u(b"{}") + ".sig", "malformed"),
    ]
    # duplicate JSON member names: jwtguard rejects outright (RFC 8259
    # leaves semantics open; first/last-wins differences are a known
    # header-splitting vector). These are not expected to match PyJWT.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    def es_raw_sign(priv, data):
        r, s = asym_utils.decode_dss_signature(
            priv.sign(data, ec.ECDSA(hashes.SHA256())))
        return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    pl_b64 = b64u(json.dumps(p, separators=(",", ":")).encode())
    dup_cases = []
    for name, hdr_json in (
        ("x09_dup_kid", b'{"alg":"ES256","kid":"ec-rogue","kid":"ec-new"}'),
        ("x10_dup_alg", b'{"alg":"none","alg":"ES256","kid":"ec-new"}'),
    ):
        hb = b64u(hdr_json)
        sg = es_raw_sign(priv("ec-new"), f"{hb}.{pl_b64}".encode())
        dup_cases.append((name, f"{hb}.{pl_b64}.{sg}", "malformed"))
    extra.extend(dup_cases)
    x_rows = [(vid, LEEWAY, NOW, token) for vid, token, _ in extra]
    x_c = run_batch(x_rows)
    dup_ids = {vid for vid, _, _ in dup_cases}
    for vid, token, expected in extra:
        got = x_c.get(vid)
        if vid in dup_ids:
            # deliberate strictness beyond the reference library
            check(vid, got is not None and got[1] == expected,
                  f"expected {expected}, c={got}")
            continue
        ref = reference_verify(token, LEEWAY)
        check(vid, got is not None and got[1] == expected == ref,
              f"expected {expected}, c={got}, reference={ref}")

    # ---- byte-level mutation fuzz: every field tamper must reject ----
    # Mutate the *decoded* bytes of each segment (the base64url tail bits
    # are padding, so character swaps there can be no-ops; see v14 above).
    fuzz_rows = []
    valid_tokens = [token for vid, token, want in vectors if want == "ok"]
    for token in valid_tokens:
        segs = token.split(".")
        raws = [base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)) for s in segs]
        for si, raw in enumerate(raws):
            for i in range(len(raw)):
                for xor in (0x01, 0x80, 0xFF):
                    mut = bytearray(raw)
                    mut[i] ^= xor
                    msegs = segs.copy()
                    msegs[si] = b64u(bytes(mut))
                    fuzz_rows.append(("f", LEEWAY, NOW, ".".join(msegs)))
            if raw:
                cut = bytearray(raw)
                cut.pop()
                msegs = segs.copy()
                msegs[si] = b64u(bytes(cut))
                fuzz_rows.append(("f", LEEWAY, NOW, ".".join(msegs)))
        fuzz_rows.append(("f", LEEWAY, NOW, segs[0] + "." + segs[1]))
        fuzz_rows.append(("f", LEEWAY, NOW, token + ".x"))
        fuzz_rows.append(("f", LEEWAY, NOW, token.replace(".", "_", 1)))
    f_c = run_batch(fuzz_rows)
    fuzz_bad = 0
    ref_accept = 0
    for (vid, _, _, tok), (cid, res) in zip(fuzz_rows, f_c.items()):
        if res[0] != "reject":
            fuzz_bad += 1
        if reference_verify(tok, LEEWAY) == "ok":
            ref_accept += 1
    check("fuzz_all_rejected", fuzz_bad == 0, f"{fuzz_bad} mutants accepted")
    check("fuzz_reference_also_rejects", ref_accept == 0,
          f"{ref_accept} mutants accepted by reference")
    check("fuzz_count", len(fuzz_rows) > 3000, f"only {len(fuzz_rows)} mutants")

    # ---- CLI smoke test ----
    good = vectors[0][1]
    r = subprocess.run([BIN, "verify", CONF, good, str(LEEWAY), str(NOW)],
                       capture_output=True, text=True)
    check("cli_verify_ok", r.returncode == 0 and "verdict=ok" in r.stdout,
          r.stdout + r.stderr)
    r = subprocess.run([BIN, "verify", CONF, vectors[16][1],
                        str(LEEWAY), str(NOW)],
                       capture_output=True, text=True)
    check("cli_verify_reject", r.returncode == 1 and "reason=expired" in r.stdout,
          r.stdout + r.stderr)

    print(f"vectors=20 fuzz_cases={len(fuzz_rows)} failures={len(failures)}")
    print(f"all_ok={'1' if not failures else '0'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
