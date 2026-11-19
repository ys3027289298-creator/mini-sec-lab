"""Independent reference chunked-body decoder (RFC 7230 section 4.1).

Written as a separate whole-buffer scanner rather than a port of
src/reqguard.c, so tests/crosscheck.py compares two implementations of the
same spec instead of comparing the C code with itself.  The C decoder is the
one exercised incrementally; this reference always sees the full input.

Limits mirror reqguard's: MAX_CHUNK_SIZE, MAX_BODY, MAX_LINE, MAX_HEADERS.
"""

MAX_CHUNK_SIZE = 4096
MAX_BODY = 4 * 4096
MAX_LINE = 256
MAX_HEADERS = 32

_HEXDIG = set("0123456789abcdefABCDEF")
_TOKEN = set("!#$%&'*+-.^_`|~") | set("0123456789") | set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class ChunkError(Exception):
    def __init__(self, status):
        self.status = status


class Result:
    def __init__(self):
        self.status = "ok"
        self.done = False
        self.chunks = 0
        self.trailers = []
        self.body = b""
        self.consumed = 0

    def as_dict(self):
        return {
            "status": self.status,
            "done": 1 if self.done else 0,
            "chunks": self.chunks,
            "trailers": len(self.trailers),
            "body_len": len(self.body),
            "consumed": self.consumed,
            "body_hex": self.body.hex(),
        }


def _parse_ext(line, i):
    """chunk-ext = *( ";" token [ "=" ( token / quoted-string ) ] )"""
    n = len(line)
    while True:
        if i >= n or line[i] != ";":
            raise ChunkError("bad_chunk_size")
        i += 1
        start = i
        while i < n and line[i] in _TOKEN:
            i += 1
        if i == start:
            raise ChunkError("bad_chunk_size")
        if i < n and line[i] == "=":
            i += 1
            if i < n and line[i] == '"':
                i += 1
                while True:
                    if i >= n:
                        raise ChunkError("bad_chunk_size")
                    c = line[i]
                    if c == '"':
                        i += 1
                        break
                    if c == "\\":
                        i += 1
                        if i >= n:
                            raise ChunkError("bad_chunk_size")
                        e = line[i]
                        if not (e == "\t" or e == " " or "\x21" <= e <= "\x7e" or ord(e) >= 0x80):
                            raise ChunkError("bad_chunk_size")
                        i += 1
                    elif (
                        c == "\t"
                        or c == " "
                        or c == "\x21"
                        or "\x23" <= c <= "\x5b"
                        or "\x5d" <= c <= "\x7e"
                        or ord(c) >= 0x80
                    ):
                        i += 1
                    else:
                        raise ChunkError("bad_chunk_size")
            else:
                start = i
                while i < n and line[i] in _TOKEN:
                    i += 1
                if i == start:
                    raise ChunkError("bad_chunk_size")
        if i >= n:
            return
        if line[i] != ";":
            raise ChunkError("bad_chunk_size")


def _size_of(line):
    n = len(line)
    i = 0
    value = 0
    while i < n and line[i] in _HEXDIG:
        value = value * 16 + int(line[i], 16)
        if value > (1 << 64) - 1:
            raise ChunkError("bad_chunk_size")
        i += 1
    if i == 0:
        raise ChunkError("bad_chunk_size")
    if i < n:
        if line[i] != ";":
            raise ChunkError("bad_chunk_size")
        _parse_ext(line, i)
    return value


def _trailer_of(line):
    """Validate a trailer field line, returning (name, value)."""
    if line[:1] in (" ", "\t"):
        raise ChunkError("bad_trailer")
    if ":" not in line:
        raise ChunkError("bad_trailer")
    name, value = line.split(":", 1)
    if name == "" or not all(c in _TOKEN for c in name):
        raise ChunkError("bad_trailer")
    value = value.strip(" \t")
    if any(ord(c) == 0x7F or (ord(c) < 0x20 and c != "\t") for c in value):
        raise ChunkError("bad_trailer")
    if name.lower() in ("transfer-encoding", "content-length"):
        raise ChunkError("bad_trailer")
    if len(name) >= 64 or len(value) >= 128:
        raise ChunkError("bad_trailer")
    return name, value


def decode(data):
    """Decode a chunked body. Returns a Result; `consumed` stops at the
    terminal CRLF so trailing pipelined bytes are excluded."""
    res = Result()
    n = len(data)
    pos = 0
    line_cr = False
    line = bytearray()
    body = bytearray()
    chunks = 0
    trailers = []

    def read_line():
        """Read one CRLF-terminated line at `pos`. Returns str, or None if
        the input ends first. Raises on a bare LF or bad terminator."""
        nonlocal pos, line_cr, line
        while pos < n:
            c = data[pos]
            pos += 1
            if line_cr:
                if c != 0x0A:
                    raise ChunkError(None)  # terminator fault, mapped by caller
                line_cr = False
                text = line.decode("latin-1")
                line = bytearray()
                return text
            if c == 0x0D:
                line_cr = True
                continue
            if c == 0x0A:
                raise ChunkError(None)
            if len(line) >= MAX_LINE:
                raise ChunkError("line_too_long")
            line.append(c)
        return None

    def fail_terminator():
        return "bad_trailer" if state[0] == "trailer" else "bad_chunk_size"

    state = ["size"]
    try:
        while True:
            if state[0] == "size":
                try:
                    raw = read_line()
                except ChunkError:
                    raise ChunkError(fail_terminator())
                if raw is None:
                    break
                size = _size_of(raw)
                chunks += 1
                if size == 0:
                    state[0] = "trailer"
                elif size > MAX_CHUNK_SIZE:
                    raise ChunkError("chunk_too_large")
                elif size > MAX_BODY - len(body):
                    raise ChunkError("too_large")
                else:
                    if pos + size > n:
                        body += data[pos:]
                        pos = n
                        break
                    body += data[pos:pos + size]
                    pos += size
                    # Consume the CRLF one byte at a time: a byte that has
                    # already arrived and is not CR/LF is an error, not
                    # "wait for more input".
                    if pos < n and data[pos] != 0x0D:
                        raise ChunkError("chunk_crlf")
                    if pos < n:
                        pos += 1
                    if pos >= n:
                        break
                    if data[pos] != 0x0A:
                        raise ChunkError("chunk_crlf")
                    pos += 1
            elif state[0] == "trailer":
                try:
                    raw = read_line()
                except ChunkError:
                    raise ChunkError("bad_trailer")
                if raw is None:
                    break
                if raw == "":
                    state[0] = "done"
                    break
                _trailer_of(raw)
                if len(trailers) >= MAX_HEADERS:
                    raise ChunkError("too_many_headers")
                trailers.append(raw)
    except ChunkError as e:
        res.status = e.status
        res.consumed = pos - len(line) - (1 if line_cr else 0)
        res.chunks = chunks
        res.trailers = trailers
        res.body = bytes(body)
        return res

    res.consumed = pos
    res.done = state[0] == "done"
    res.chunks = chunks
    res.trailers = trailers
    res.body = bytes(body)
    return res


if __name__ == "__main__":
    import sys

    raw = bytes.fromhex(sys.stdin.read())
    for k, v in decode(raw).as_dict().items():
        print(f"{k}={v}")
