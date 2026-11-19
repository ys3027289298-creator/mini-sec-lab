#!/usr/bin/env python3
"""Regenerate src/hpack_tables.h from the RFC 7541 text.

Usage: python3 tools/gen_tables.py path/to/rfc7541.txt
The RFC text is fetched from https://www.rfc-editor.org/rfc/rfc7541.txt.
The generated header is checked in, so this is only needed to audit or
rebuild the constant tables.
"""
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
rfc = sys.argv[1] if len(sys.argv) > 1 else 'rfc7541.txt'
text = open(rfc).read()
a = text.index('Appendix A.  Static Table Definition')
b = text.index('Appendix B.  Huffman Code')
rows = re.findall(r'\|\s*(\d+)\s*\|\s*([!-~]+)\s*\|\s*([!-~ ]*?)\s*\|', text[a:b])
assert len(rows) == 61
body = text[b:]
pat = re.compile(r'\(\s*(\d+)\)\s*\|[01|]+\s+([0-9a-f]+)\s+\[\s*(\d+)\]')
codes = {int(s): (int(c, 16), int(l)) for s, c, l in pat.findall(body)}
m = re.search(r'EOS\s*\(256\)\s*\|[01|]+\s+([0-9a-f]+)\s+\[\s*(\d+)\]', body)
codes[256] = (int(m.group(1), 16), int(m.group(2)))
assert len(codes) == 257 and sorted(codes) == list(range(257))

from collections import defaultdict
bylen = defaultdict(list)
for s, (c, l) in codes.items():
    bylen[l].append((c, s))
first, count, off, syms = {}, {}, {}, []
for l in sorted(bylen):
    v = sorted(bylen[l])
    first[l], count[l], off[l] = v[0][0], len(v), len(syms)
    syms.extend(s for c, s in v)
maxlen = max(bylen)

def carr(name, typ, vals, per, fmt, wrap=True):
    n = 'HPACK_TRIE_NODES' if name.startswith('huff_child') or name == 'huff_sym' else len(vals)
    out = ['static const %s %s[%s] = {' % (typ, name, n)]
    for i in range(0, len(vals), per):
        out.append('    ' + ', '.join(fmt(v) for v in vals[i:i + per]) + ',')
    out.append('};')
    return '\n'.join(out)

# Huffman trie
tri = [[-1, -1, -1]]
for sym in range(257):
    code, l = codes[sym]
    node = 0
    for k in range(l - 1, -1, -1):
        bit = (code >> k) & 1
        nxt = tri[node][bit]
        if k == 0:
            assert nxt == -1
            tri.append([-1, -1, sym])
            tri[node][bit] = len(tri) - 1
        else:
            if nxt == -1:
                tri.append([-1, -1, -1])
                nxt = len(tri) - 1
                tri[node][bit] = nxt
            node = nxt
assert sum(1 for t in tri if t[2] >= 0) == 257

L = []
L.append('/* Generated from RFC 7541 Appendices A and B. Do not edit by hand.\n'
         '   Included only by hpack.c. */\n'
         '#ifndef REQGUARD_HPACK_TABLES_H\n#define REQGUARD_HPACK_TABLES_H\n\n'
         '#include <stdint.h>\n\n#define HPACK_STATIC_COUNT 61\n\n'
         'typedef struct {\n'
         '    const char *name;\n'
         '    const char *value;\n'
         '    uint8_t name_len;\n'
         '    uint8_t value_len;\n'
         '} HpackStaticEntry;\n')
L.append('#define HSE(n, v) { n, v, sizeof(n) - 1, sizeof(v) - 1 }')
L.append('\n/* RFC 7541 Appendix A. Index 0 is unused: the table is 1-based. */\n'
         'static const HpackStaticEntry hpack_static[HPACK_STATIC_COUNT + 1] = {')
L.append('    { 0, 0, 0, 0 },')
for idx, n, v in rows:
    L.append('    HSE("%s", "%s"), /* %s */' % (n, v, idx))
L.append('};\n')
L.append('/* RFC 7541 Appendix B Huffman code indexed by symbol; 256 is EOS.\n'
         '   The decoder walks huff_child0/huff_child1; the code and length\n'
         '   arrays are exported for encoders (self-tests). */')
L.append(carr('huff_code', 'uint32_t', [codes[i][0] for i in range(257)], 8, lambda v: '0x%08x' % v).replace('static const uint32_t huff_code', 'const uint32_t hpack_huff_code'))
L.append(carr('huff_len', 'uint8_t', [codes[i][1] for i in range(257)], 16, lambda v: '%2d' % v).replace('static const uint8_t huff_len', 'const uint8_t hpack_huff_len'))
L.append('\n/* Binary trie over the same code. Walking bit by bit, huff_sym[node]\n'
         '   is the EOS-including symbol for a leaf and -1 for an internal\n'
         '   node; an incomplete path at end of input is EOS padding. */')
L.append('#define HPACK_TRIE_NODES %d' % len(tri))
L.append(carr('huff_child0', 'int16_t', [t[0] for t in tri], 16, lambda v: '%d' % v))
L.append(carr('huff_child1', 'int16_t', [t[1] for t in tri], 16, lambda v: '%d' % v))
L.append(carr('huff_sym', 'int16_t', [t[2] for t in tri], 16, lambda v: '%d' % v))
L.append('\n#endif /* REQGUARD_HPACK_TABLES_H */')
open(os.path.join(here, '..', 'src', 'hpack_tables.h'), 'w').write('\n'.join(L) + '\n')
print('ok trie nodes', len(tri))
