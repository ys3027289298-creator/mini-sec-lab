#!/usr/bin/env python3
"""Independent HPACK reference decoder, written from RFC 7541 and the
HTTP/2 field rules in RFC 9113. Shares no code with the C implementation.

The script on stdin drives a connection:
    table N        set the advertised SETTINGS_HEADER_TABLE_SIZE
    block HEX      decode one field section and validate it as a request

Each block prints the fields the decoder produced (including the field
that fails validation, as a connection would need it for its trace),
then the request-level result and the dynamic table state. Output is
compared byte for byte with `reqguard h2trace` by hpack_crosscheck.py.

Run:  python3 -I tools/ref_hpack.py < script
"""
import sys

# Generated from RFC 7541 Appendix B. Do not edit by hand.
HUFF_CODE = (
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0, 1, 2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 3, 0x23, 4, 0x24, 5, 0x25, 0x26,
    0x27, 6, 0x74, 0x75, 0x28, 0x29, 0x2a, 7,
    0x2b, 0x76, 0x2c, 8, 9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    0x3fffffff,
)
HUFF_LEN = (
    0xd, 0x17, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c,
    0x1c, 0x18, 0x1e, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c,
    0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1e, 0x1c,
    0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c,
    6, 0xa, 0xa, 0xc, 0xd, 6, 8, 0xb,
    0xa, 0xa, 8, 0xb, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6,
    6, 6, 7, 8, 0xf, 6, 0xc, 0xa,
    0xd, 6, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    8, 7, 8, 0xd, 0x13, 0xd, 0xe, 6,
    0xf, 5, 6, 5, 6, 5, 6, 6,
    6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7,
    7, 7, 7, 0xf, 0xb, 0xe, 0xd, 0x1c,
    0x14, 0x16, 0x14, 0x14, 0x16, 0x16, 0x16, 0x17,
    0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x18, 0x17,
    0x18, 0x18, 0x16, 0x17, 0x18, 0x17, 0x17, 0x17,
    0x17, 0x15, 0x16, 0x17, 0x16, 0x17, 0x17, 0x18,
    0x16, 0x15, 0x14, 0x16, 0x16, 0x17, 0x17, 0x15,
    0x17, 0x16, 0x16, 0x18, 0x15, 0x16, 0x17, 0x17,
    0x15, 0x15, 0x16, 0x15, 0x17, 0x16, 0x17, 0x17,
    0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x16, 0x17,
    0x1a, 0x1a, 0x14, 0x13, 0x16, 0x17, 0x16, 0x19,
    0x1a, 0x1a, 0x1a, 0x1b, 0x1b, 0x1a, 0x18, 0x19,
    0x13, 0x15, 0x1a, 0x1b, 0x1b, 0x1a, 0x1b, 0x18,
    0x15, 0x15, 0x1a, 0x1a, 0x1c, 0x1b, 0x1b, 0x1b,
    0x14, 0x18, 0x14, 0x15, 0x16, 0x15, 0x15, 0x17,
    0x16, 0x16, 0x19, 0x19, 0x18, 0x18, 0x1a, 0x17,
    0x1a, 0x1b, 0x1a, 0x1a, 0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1c, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1a,
    0x1e,
)


STATIC = [
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"),
    (b":path", b"/"), (b":path", b"/index.html"), (b":scheme", b"http"),
    (b":scheme", b"https"), (b":status", b"200"), (b":status", b"204"),
    (b":status", b"206"), (b":status", b"304"), (b":status", b"400"),
    (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""),
    (b"accept-ranges", b""), (b"accept", b""),
    (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""),
    (b"content-disposition", b""), (b"content-encoding", b""),
    (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""),
    (b"content-type", b""), (b"cookie", b""), (b"date", b""), (b"etag", b""),
    (b"expect", b""), (b"expires", b""), (b"from", b""), (b"host", b""),
    (b"if-match", b""), (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""), (b"last-modified", b""),
    (b"link", b""), (b"location", b""), (b"max-forwards", b""),
    (b"proxy-authenticate", b""), (b"proxy-authorization", b""),
    (b"range", b""), (b"referer", b""), (b"refresh", b""),
    (b"retry-after", b""), (b"server", b""), (b"set-cookie", b""),
    (b"strict-transport-security", b""), (b"transfer-encoding", b""),
    (b"user-agent", b""), (b"vary", b""), (b"via", b""),
    (b"www-authenticate", b""),
]

DENIED = {b"connection", b"proxy-connection", b"keep-alive",
          b"transfer-encoding", b"upgrade"}
TCHAR = set(b"!#$%&'*+-.^_`|~")


class Err(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


# ---- Huffman (Appendix B): decode trie built from the code table.
def _trie():
    trie = {}
    for sym in range(257):
        code, ln = HUFF_CODE[sym], HUFF_LEN[sym]
        node = trie
        for k in range(ln - 1, -1, -1):
            bit = (code >> k) & 1
            if k == 0:
                node[bit] = sym
            else:
                node = node.setdefault(bit, {})
    return trie


TRIE = _trie()


def huffman_decode(data):
    node = TRIE
    out = bytearray()
    pad_bits = 0
    pad_ones = True
    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            if bit not in node:
                raise Err("hpack_huffman")
            node = node[bit]
            pad_bits += 1
            if bit == 0:
                pad_ones = False
            if isinstance(node, int):
                if node == 256:
                    raise Err("hpack_huffman")
                out.append(node)
                node = TRIE
                pad_bits = 0
                pad_ones = True
    if pad_bits > 7:
        raise Err("hpack_huffman")
    if pad_bits > 0 and not pad_ones:
        raise Err("hpack_huffman")
    return bytes(out)


class Conn:
    def __init__(self):
        self.allowed = 4096
        self.dynamic = []          # newest first
        self.size = 0
        self.max_size = 4096
        self.needs_shrink_update = False
        self.shrink_target = 1 << 32

    # ---- table helpers
    def evict(self, limit):
        while self.size > limit and self.dynamic:
            n, v = self.dynamic.pop()
            self.size -= 32 + len(n) + len(v)
        if not self.dynamic:
            self.size = 0

    def resize(self, new_max):
        self.max_size = new_max
        self.evict(new_max)

    def add(self, name, value):
        entry = 32 + len(name) + len(value)
        self.evict(0 if entry > self.max_size else self.max_size - entry)
        if entry > self.max_size:
            return
        self.dynamic.insert(0, (name, value))
        self.size += entry

    def entry(self, index):
        if index == 0:
            raise Err("hpack_index_zero")
        if index <= len(STATIC):
            return STATIC[index - 1]
        i = index - len(STATIC) - 1
        if i >= len(self.dynamic):
            raise Err("hpack_index_range")
        return self.dynamic[i]

    # ---- representation decoding
    def integer(self, data, pos, prefix):
        if pos >= len(data):
            raise Err("hpack_truncated")
        mask = (1 << prefix) - 1
        value = data[pos] & mask
        pos += 1
        if value < mask:
            return value, pos
        shift = 0
        while True:
            if pos >= len(data):
                raise Err("hpack_truncated")
            b = data[pos]
            pos += 1
            if shift > 28:
                raise Err("hpack_integer_overflow")
            if shift == 28 and (b & 0x7f) > 0x0f:
                raise Err("hpack_integer_overflow")
            value += (b & 0x7f) << shift
            if not (b & 0x80):
                return value, pos
            shift += 7

    def string(self, data, pos):
        if pos >= len(data):
            raise Err("hpack_truncated")
        huff = bool(data[pos] & 0x80)
        length, pos = self.integer(data, pos, 7)
        if length > len(data) - pos:
            raise Err("hpack_truncated")
        raw = data[pos:pos + length]
        pos += length
        if huff:
            return huffman_decode(raw), pos
        return raw, pos

    def field_name(self, data, pos, prefix):
        index, pos = self.integer(data, pos, prefix)
        if index == 0:
            name, pos = self.string(data, pos)
            return name, pos
        return self.entry(index)[0], pos

    def decode(self, data):
        pos = 0
        fields = []
        inflated = 0
        updates = 0
        smallest = 1 << 32
        seen_field = False
        err = None
        try:
            while pos < len(data):
                b = data[pos]
                if b & 0x80:
                    index, pos = self.integer(data, pos, 7)
                    if index == 0:
                        raise Err("hpack_index_zero")
                    if index <= len(STATIC):
                        name, value = STATIC[index - 1]
                    else:
                        i = index - len(STATIC) - 1
                        if i >= len(self.dynamic):
                            raise Err("hpack_index_range")
                        name, value = self.dynamic[i]
                    fields.append((name, value))
                elif b & 0x40:
                    name, pos = self.field_name(data, pos, 6)
                    value, pos = self.string(data, pos)
                    fields.append((name, value))
                    self.add(name, value)
                    field = (name, value)
                elif b & 0x20:
                    if seen_field or updates >= 2:
                        raise Err("hpack_size_update_after_field")
                    updates += 1
                    nmax, pos = self.integer(data, pos, 5)
                    if nmax > self.allowed:
                        raise Err("hpack_table_size_update_exceeds_max")
                    smallest = min(smallest, nmax)
                    self.resize(nmax)
                    continue
                else:
                    name, pos = self.field_name(data, pos, 4)
                    value, pos = self.string(data, pos)
                    fields.append((name, value))
                seen_field = True
                inflated += 32 + len(fields[-1][0]) + len(fields[-1][1])
                if inflated > 65536:
                    raise Err("hpack_header_list_too_large")
            if self.max_size > self.allowed:
                raise Err("hpack_size_update_missing")
            if self.needs_shrink_update and smallest > self.shrink_target:
                raise Err("hpack_size_update_missing")
            self.needs_shrink_update = False
            self.shrink_target = 1 << 32
        except Err as e:
            err = e.name
        except IndexError:
            err = "hpack_truncated"
        return fields, err


# ---- request validation (RFC 9113 8.2/8.3)

def name_ok(name, pseudo):
    if not name:
        return False
    for i, c in enumerate(name):
        if c <= 0x20 or 0x41 <= c <= 0x5a or c >= 0x7f:
            return False
        if c == 0x3a and not (pseudo and i == 0):
            return False
    return True


def value_ok(value):
    if not value:
        return True
    if value[0] in (0x20, 0x09) or value[-1] in (0x20, 0x09):
        return False
    return not any(c in (0x00, 0x0d, 0x0a) for c in value)


def is_token(b):
    return all(chr(c).isalnum() and c < 128 or c in TCHAR for c in b)


def validate(fields):
    """Return (result_name, method, scheme, path, authority, headers, cl)."""
    st = {"method": False, "scheme": False, "path": False,
          "authority": False, "seen_regular": False, "seen_cl": False}
    method = scheme = path = authority = b""
    headers = []
    cl = -1
    for name, value in fields:
        pseudo = bool(name) and name[0] == 0x3a
        if not name_ok(name, pseudo):
            return "h2_field_name", None
        if not value_ok(value):
            return "h2_field_value", None
        if pseudo and st["seen_regular"]:
            return "h2_pseudo_order", None
        if pseudo:
            key = {b":method": "method", b":scheme": "scheme",
                   b":path": "path", b":authority": "authority"}.get(name)
            if key is None:
                return "h2_pseudo_unknown", None
            if st[key]:
                return "h2_pseudo_dup", None
            st[key] = True
            if key == "method":
                if not value or len(value) >= 16 or not is_token(value):
                    return "h2_pseudo_value", None
                method = value
            elif key == "scheme":
                if not value or len(value) >= 16:
                    return "h2_pseudo_value", None
                scheme = value
            elif key == "path":
                if not value or len(value) >= 128:
                    return "h2_pseudo_value", None
                path = value
            else:
                if len(value) >= 128:
                    return "h2_pseudo_value", None
                authority = value
            continue
        st["seen_regular"] = True
        if name in DENIED:
            return "h2_connection_header", None
        if name == b"te":
            if not (value == b"trailers" or value.lower() == b"trailers"):
                return "h2_te_value", None
        if name == b"content-length":
            if st["seen_cl"]:
                return "dup_content_length", None
            st["seen_cl"] = True
            if not value or not all(0x30 <= c <= 0x39 for c in value):
                return "bad_content_length", None
            if int(value) > 2147483647:
                return "bad_content_length", None
            cl = int(value)
        if len(name) >= 64 or len(value) >= 1024:
            return "too_large", None
        if len(headers) >= 32:
            return "too_many_headers", None
        headers.append((name, value))

    if not st["method"]:
        return "h2_pseudo_missing", None
    if method == b"CONNECT":
        if not st["authority"]:
            return "h2_pseudo_missing", None
        if st["scheme"] or st["path"]:
            return "h2_pseudo_value", None
        path = authority
    else:
        if not st["scheme"] or not st["path"]:
            return "h2_pseudo_missing", None
        if not path.startswith(b"/") and path != b"*":
            return "h2_pseudo_value", None
    return "ok", (method, scheme, path, authority, headers, cl)


def esc(b):
    out = []
    for c in b:
        if 0x20 <= c <= 0x7e and c != 0x5c:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    return "".join(out)


def run_script(text):
    conn = Conn()
    out = []
    block_no = 0
    rc = 0
    for line in text.splitlines():
        # Trim only the line ending: the C driver parses the same bytes.
        line = line.rstrip("\r\n")
        if not line or line.startswith("#"):
            continue
        if line.startswith("table "):
            v = int(line[6:])
            if v > 65536:
                out.append("table max=%d accepted=0" % v)
                out.append("result=hpack_table_size_limit")
                rc = 1
                break
            if v < conn.allowed:
                conn.needs_shrink_update = True
                conn.shrink_target = min(conn.shrink_target, v)
            conn.allowed = v
            out.append("table max=%d accepted=1" % v)
            continue
        if line.startswith("block "):
            data = bytes.fromhex(line[6:])
            out.append("block %d" % block_no)
            block_no += 1
            fields, err = conn.decode(data)
            for name, value in fields:
                out.append("field %s %s" % (esc(name), esc(value)))
            if err is not None:
                out.append("result=%s" % err)
            else:
                result, _ = validate(fields)
                out.append("result=%s" % result)
            out.append("table size=%d entries=%d max=%d"
                       % (conn.size, len(conn.dynamic), conn.max_size))
            continue
        raise SystemExit("bad script line")
    return "\n".join(out) + "\n", rc


def main():
    text = sys.stdin.read()
    sys.stderr.write("")  # keep stdout pure
    out, rc = run_script(text)
    sys.stdout.write(out)
    return rc


if __name__ == "__main__":
    sys.exit(main())
