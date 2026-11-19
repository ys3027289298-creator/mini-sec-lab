#!/usr/bin/env python3
"""Independent reference parser + 30-message vector generator for tlsrecord.

This file shares no code with the C implementation: the reference engine
is written from RFC 5246 6.2.1 and the project requirements, then emits
the same normalized trace as `tlsrecord dump`. The C/Python outputs are
diffed by tools/refcheck.sh for field-by-field parity.

Run:  python3 -I tools/gen_vectors.py <out_dir>
"""
import os
import sys

MAX_RECORD_PLAINTEXT = 16384
MAX_HANDSHAKE_MSG = 65536

# error codes must match the C TrlErr enum values
ERR = {
    "ok": 0,
    "record_too_large": 1,
    "bad_version": 2,
    "bad_type": 3,
    "length_mismatch": 4,
    "handshake_truncated": 5,
    "handshake_too_large": 6,
    "handshake_overlap": 7,
    "handshake_reorder": 8,
    "handshake_length_conflict": 9,
    "renegotiation_rejected": 10,
    "ccs_after_established": 11,
    "app_overflow": 12,
    "truncated_stream": 13,
}

TNAME = {20: "change_cipher_spec", 21: "alert",
         22: "handshake", 23: "application_data"}


# ---------------------------------------------------------------- wire
def record(rtype, ver, body):
    return bytes([rtype, (ver >> 8) & 0xff, ver & 0xff,
                  (len(body) >> 8) & 0xff, len(body) & 0xff]) + body


def hs_frag(htype, hlen, seq, foff, frag):
    return (bytes([htype, (hlen >> 16) & 0xff, (hlen >> 8) & 0xff, hlen & 0xff,
                   (seq >> 8) & 0xff, seq & 0xff,
                   (foff >> 16) & 0xff, (foff >> 8) & 0xff, foff & 0xff,
                   (len(frag) >> 16) & 0xff, (len(frag) >> 8) & 0xff,
                   len(frag) & 0xff]) + frag)


def pattern(n, seed=1):
    return bytes(((i * 7 + seed) & 0xff) for i in range(n))


# ------------------------------------------------- reference record engine
class RefEngine:
    def __init__(self, allow_ccs_after=False):
        self.type_allow = {20, 21, 22, 23}
        self.allow_ccs_after = allow_ccs_after
        self.established = False
        self.hs_active = False
        self.hs_type = 0
        self.hs_total = 0
        self.hs_got = 0
        self.hs_seq = 0
        self.hs = bytearray()
        self.app = bytearray()
        self.n_records = 0
        self.n_hs_messages = 0
        self.n_frags = 0
        self.n_reordered = 0
        self.n_duplicates = 0
        self.dup_bytes = 0
        self.n_alerts = 0
        self.last_alert_level = 0
        self.last_alert_desc = 0
        self.last_err = "ok"
        self.last_detail = 0

    def _fail(self, name, detail):
        self.last_err = name
        self.last_detail = detail
        return name

    def _dispatch_handshake(self, body):
        pos = 0
        n = len(body)
        while pos < n:
            if n - pos < 12:
                return self._fail("handshake_truncated", n - pos)
            htype = body[pos]
            hlen = int.from_bytes(body[pos + 1:pos + 4], "big")
            mseq = int.from_bytes(body[pos + 4:pos + 6], "big")
            foff = int.from_bytes(body[pos + 6:pos + 9], "big")
            flen = int.from_bytes(body[pos + 9:pos + 12], "big")
            self.n_frags += 1

            if hlen > MAX_HANDSHAKE_MSG:
                return self._fail("handshake_too_large", hlen)
            if pos + 12 + flen > n:
                return self._fail("handshake_truncated", flen)
            if foff + flen > hlen:
                return self._fail("handshake_length_conflict", foff + flen)

            if not self.hs_active:
                if foff != 0:
                    self.n_reordered += 1
                    return self._fail("handshake_reorder", foff)
                self.hs_active = True
                self.hs_type = htype
                self.hs_total = hlen
                self.hs_seq = mseq
                self.hs_got = 0
                self.hs = bytearray(hlen)
            elif htype != self.hs_type or hlen != self.hs_total:
                return self._fail("handshake_length_conflict", hlen)
            if mseq != self.hs_seq:
                self.n_reordered += 1
                return self._fail("handshake_reorder", mseq)

            end = foff + flen
            if flen > 0 and foff < self.hs_got:
                if end <= self.hs_got:
                    if bytes(self.hs[foff:end]) != body[pos + 12:pos + 12 + flen]:
                        return self._fail("handshake_overlap", foff)
                    self.n_duplicates += 1
                    self.dup_bytes += flen
                else:
                    return self._fail("handshake_overlap", foff)
            elif flen > 0 and foff > self.hs_got:
                self.n_reordered += 1
                return self._fail("handshake_reorder", foff)
            elif flen > 0:
                self.hs[foff:end] = body[pos + 12:pos + 12 + flen]
                if end > self.hs_got:
                    self.hs_got = end

            if self.hs_got == self.hs_total:
                self.n_hs_messages += 1
                self.hs_active = False
                self.hs_got = 0
            pos += 12 + flen
        if pos != n:
            return self._fail("length_mismatch", pos)
        return "ok"

    def feed_record(self, rtype, ver, body):
        length = len(body)
        self.n_records += 1
        if rtype not in self.type_allow:
            return self._fail("bad_type", rtype)
        if ver not in (0x0301, 0x0303):
            return self._fail("bad_version", ver)
        if length == 0:
            return self._fail("length_mismatch", length)
        if rtype == 20 and length != 1:
            return self._fail("length_mismatch", length)
        if rtype == 21 and length != 2:
            return self._fail("length_mismatch", length)

        if rtype == 23:
            if len(self.app) + length > MAX_RECORD_PLAINTEXT:
                return self._fail("app_overflow", len(self.app) + length)
            self.app += body
        elif rtype == 22:
            if self.established:
                return self._fail("renegotiation_rejected", rtype)
            rc = self._dispatch_handshake(body)
            if rc != "ok":
                return rc
        elif rtype == 20:
            if self.established and not self.allow_ccs_after:
                return self._fail("ccs_after_established", body[0])
        elif rtype == 21:
            self.n_alerts += 1
            self.last_alert_level = body[0]
            self.last_alert_desc = body[1]
        return "ok"


# --------------------------------------------------------- HTTP (reqguard port)
def _is_token(s):
    tchars = set(b"!#$%&'*+-.^_`|~")
    return all((65 <= c <= 90) or (97 <= c <= 122) or (48 <= c <= 57)
               or c in tchars for c in s)


def http_reqguard(data):
    """Faithful mini-port of reqguard's parser over a single request buffer."""
    if len(data) > 4096:
        return "too_large"
    data = bytes(data)
    for c in data:
        if c == 0 or (c < 0x20 and c not in (0x0d, 0x0a, 0x09)):
            return "control_char"

    def next_line(buf, pos):
        start = pos
        while pos + 1 < len(buf):
            if buf[pos] == 0x0d and buf[pos + 1] == 0x0a:
                return buf[start:pos], pos + 2
            pos += 1
        return None, pos

    line, pos = next_line(data, 0)
    if line is None or len(line) > 256:
        return "line_too_long"
    parts = line.split(b" ")
    if len(parts) != 3:
        return "bad_method" if len(parts) < 3 else "bad_target"
    method, target, version = parts
    if not method or len(method) >= 16 or not _is_token(method):
        return "bad_method"
    if not target.startswith(b"/") or len(target) >= 128:
        return "bad_target"
    if any(c <= 0x20 or c == 0x7f for c in target):
        return "bad_target"
    if not version.startswith(b"HTTP/1.") or len(version) != 8 \
            or version[7] not in (ord("0"), ord("1")):
        return "bad_version"

    seen_cl = False
    has_te = False
    hcount = 0
    while True:
        line, pos = next_line(data, pos)
        if line is None:
            return "line_too_long"
        if len(line) == 0:
            break
        if line[0] in (ord(" "), ord("\t")):
            return "obs_fold"
        if b":" not in line or line[0] == ord(":"):
            return "bad_header"
        name, _, value = line.partition(b":")
        if not _is_token(name):
            return "bad_header"
        value = value.strip(b" \t")
        if any(c == 0x7f for c in value):
            return "control_char"
        hcount += 1
        if hcount > 32:
            return "too_many_headers"
        if name.lower() == b"content-length":
            if seen_cl:
                return "dup_content_length"
            seen_cl = True
            if not value.isdigit():
                return "bad_content_length"
        elif name.lower() == b"transfer-encoding":
            has_te = True
    if has_te and seen_cl:
        return "cl_te_conflict"
    return "ok"


# --------------------------------------------------------- normalized dump
def run_dump(blob, established=False, allow_ccs_after=False):
    eng = RefEngine(allow_ccs_after)
    eng.established = established
    out = []
    size = len(blob)
    off = 0
    stream_pos = 0
    rc = "ok"
    while off < size:
        if off + 5 > size:
            rc = eng._fail("truncated_stream", size - off)
            break
        rtype = blob[off]
        ver = int.from_bytes(blob[off + 1:off + 3], "big")
        length = int.from_bytes(blob[off + 3:off + 5], "big")
        out.append("record type=%s(%u) ver=0x%04x len=%u offset=%d"
                   % (TNAME.get(rtype, "unknown"), rtype, ver, length, stream_pos))
        if length > MAX_RECORD_PLAINTEXT:
            # the engine reads the five header bytes and rejects immediately
            rc = eng._fail("record_too_large", length)
            break
        total = 5 + length
        if off + total > size:
            rc = eng._fail("truncated_stream", size - off)
            break
        if rtype == 22 and not eng.established:
            p = off + 5
            end = off + 5 + length
            while p < end:
                if end - p < 12:
                    out.append("  fragment truncated=1 remain=%d" % (end - p))
                    break
                ht = blob[p]
                hl = int.from_bytes(blob[p + 1:p + 4], "big")
                ms = int.from_bytes(blob[p + 4:p + 6], "big")
                fo = int.from_bytes(blob[p + 6:p + 9], "big")
                fl = int.from_bytes(blob[p + 9:p + 12], "big")
                out.append("  fragment hs_type=%u hs_len=%u seq=%u "
                           "frag_off=%u frag_len=%u" % (ht, hl, ms, fo, fl))
                if p + 12 + fl > end:
                    out.append("  fragment truncated=1 remain=%d" % (end - p - 12))
                    break
                p += 12 + fl
        elif rtype == 21 and length == 2:
            out.append("  alert level=%u desc=%u" % (blob[off + 5], blob[off + 6]))
        rc = eng.feed_record(rtype, ver, blob[off + 5:off + 5 + length])
        if rc != "ok":
            break
        off += total
        stream_pos += total

    out.append("result=%s" % rc +
               (" code=%d detail=%d" % (ERR[rc], eng.last_detail)
                if rc != "ok" else ""))
    out.append("stats records=%d hs_messages=%d fragments=%d reordered=%d "
               "duplicates=%d dup_bytes=%d alerts=%d app_bytes=%d"
               % (eng.n_records, eng.n_hs_messages, eng.n_frags,
                  eng.n_reordered, eng.n_duplicates, eng.dup_bytes,
                  eng.n_alerts, len(eng.app)))
    http = http_reqguard(bytes(eng.app[:4096])) if eng.app else "none"
    out.append("http=%s" % http)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- 30 vectors
def build_vectors():
    v = []
    msg = pattern(40)

    # 01 simple application_data
    v.append(("v01_app_simple", {}, record(23, 0x0303, b"PING")))
    # 02 max-size record (16384)
    v.append(("v02_max_record", {}, record(23, 0x0303, pattern(16384))))
    # 03 two records in one stream
    v.append(("v03_two_records", {},
              record(23, 0x0303, b"AB") + record(23, 0x0303, b"CD")))
    # 04 TLS 1.0 version accepted
    v.append(("v04_tls10", {}, record(23, 0x0301, b"X")))
    # 05 handshake single fragment whole message
    v.append(("v05_hs_whole", {},
              record(22, 0x0303, hs_frag(22, 40, 0, 0, msg))))
    # 06 handshake two fragments
    v.append(("v06_hs_two_frag", {},
              record(22, 0x0303,
                     hs_frag(22, 40, 0, 0, msg[:20]) +
                     hs_frag(22, 40, 0, 20, msg[20:]))))
    # 07 handshake across two records
    v.append(("v07_hs_across_records", {},
              record(22, 0x0303, hs_frag(22, 40, 0, 0, msg[:20])) +
              record(22, 0x0303, hs_frag(22, 40, 0, 20, msg[20:]))))
    # 08 multiple handshake messages in one record
    v.append(("v08_hs_multi_msg", {},
              record(22, 0x0303,
                     hs_frag(1, 8, 0, 0, pattern(8, 2)) +
                     hs_frag(2, 8, 1, 0, pattern(8, 3)))))
    # 09 CCS
    v.append(("v09_ccs", {}, record(20, 0x0303, b"\x01")))
    # 10 alert
    v.append(("v10_alert", {}, record(21, 0x0303, b"\x02\x28")))
    # 11 mixed alert + handshake + app
    v.append(("v11_mixed", {},
              record(21, 0x0303, b"\x02\x28") +
              record(22, 0x0303, hs_frag(22, 16, 0, 0, pattern(16))) +
              record(23, 0x0303, b"DATA")))
    # 12 empty app record (illegal: length mismatch)
    v.append(("v12_empty_app", {}, record(23, 0x0303, b"")))
    # 13 illegal type 24
    v.append(("v13_bad_type", {}, record(24, 0x0303, b"\x01")))
    # 14 SSL 3.0 version
    v.append(("v14_bad_version", {}, record(23, 0x0300, b"Z")))
    # 15 oversized record (16385) — header only, no payload
    v.append(("v15_oversized", {},
              bytes([23, 0x03, 0x03, 0x40, 0x01])))
    # 16 CCS length 2
    v.append(("v16_ccs_len2", {}, record(20, 0x0303, b"\x01\x02")))
    # 17 alert length 3
    v.append(("v17_alert_len3", {}, record(21, 0x0303, b"\x02\x28\x00")))
    # 18 handshake reorder: gap at offset 25 after 0..19
    v.append(("v18_hs_reorder", {},
              record(22, 0x0303,
                     hs_frag(22, 40, 0, 0, msg[:20]) +
                     hs_frag(22, 40, 0, 25, msg[25:]))))
    # 19 handshake overlap with altered byte
    tampered = bytearray(msg[10:30]); tampered[0] ^= 0xff
    v.append(("v19_hs_overlap", {},
              record(22, 0x0303,
                     hs_frag(22, 40, 0, 0, msg[:20]) +
                     hs_frag(22, 40, 0, 10, bytes(tampered)))))
    # 20 identical retransmit accepted as duplicate
    v.append(("v20_hs_duplicate", {},
              record(22, 0x0303,
                     hs_frag(22, 40, 0, 0, msg[:20]) +
                     hs_frag(22, 40, 0, 0, msg[:20]) +
                     hs_frag(22, 40, 0, 20, msg[20:]))))
    # 21 fragment length conflicts with declared total
    v.append(("v21_hs_len_conflict", {},
              record(22, 0x0303, hs_frag(22, 20, 0, 0, msg[:21]))))
    # 22 fragment truncated: header claims 16 bytes, record has 1
    v.append(("v22_hs_truncated", {},
              bytes([22, 0x03, 0x03, 0x00, 0x08]) +
              bytes([22, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 16, 0x41])))
    # 23 reassembled message exceeds 65536
    v.append(("v23_hs_too_large", {},
              record(22, 0x0303,
                     hs_frag(22, MAX_HANDSHAKE_MSG + 1, 0, 0, pattern(300)))))
    # 24 truncated stream: 3 header bytes only
    v.append(("v24_trunc_header", {}, bytes([23, 0x03, 0x03])))
    # 25 truncated stream: full header, 8 of 10 payload bytes
    v.append(("v25_trunc_body", {},
              bytes([23, 0x03, 0x03, 0x00, 0x0a]) + b"01234567"))
    # 26 renegotiation after established (sidecar drives the state)
    v.append(("v26_renegotiation", {"established": "1"},
              record(22, 0x0303, hs_frag(0, 0, 0, 0, b""))))
    # 27 CCS after established, default policy: rejected
    v.append(("v27_ccs_est_deny", {"established": "1"},
              record(20, 0x0303, b"\x01")))
    # 28 CCS after establishment with the permissive policy: accepted
    v.append(("v28_ccs_est_allow",
              {"established": "1", "allow_ccs_after": "1"},
              record(20, 0x0303, b"\x01")))
    # 29 valid HTTP request through the reqguard entry
    v.append(("v29_http_ok", {},
              record(23, 0x0303, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")))
    # 30 CL+TE request smuggling caught by reqguard
    v.append(("v30_http_smuggling", {},
              record(23, 0x0303,
                     b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n")))
    return v


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "vectors"
    os.makedirs(outdir, exist_ok=True)
    vectors = build_vectors()
    for name, sidecar, blob in vectors:
        with open(os.path.join(outdir, name + ".bin"), "wb") as f:
            f.write(blob)
        if sidecar:
            with open(os.path.join(outdir, name + ".ctl"), "w") as f:
                for k, val in sidecar.items():
                    f.write("%s=%s\n" % (k, val))
        with open(os.path.join(outdir, name + ".expected"), "w") as f:
            f.write(run_dump(blob,
                             established=sidecar.get("established") == "1",
                             allow_ccs_after=sidecar.get("allow_ccs_after") == "1"))
    print("generated %d vectors in %s" % (len(vectors), outdir))


if __name__ == "__main__":
    main()
