#!/usr/bin/env python3
"""Cross-check reqguard's HPACK/HTTP2 path against tools/ref_hpack.py.

Every case is a connection script ("table N" / "block HEX") run through
both `reqguard h2trace` and the independent Python reference. Their
whole traces -- decoded fields, request-level result and dynamic table
state after each block -- must match exactly.

Cases cover the RFC 7541 Appendix C request and response sequences
(eviction under a 256-byte table), Huffman and raw literals, dynamic
table reuse, size updates, and every rejection the validator can make.

Run from reqguard/:  python3 -I tools/hpack_crosscheck.py
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BINARY = os.path.join(ROOT, "reqguard")
REF = os.path.join(HERE, "ref_hpack.py")

# Field blocks as hex. Where a sequence shares a connection, the blocks
# are concatenated in one script so the dynamic table carries over.
C = "828684418cf1e3c2e5f23a6ba0ab90f4ff"          # C.4.1
C_NO_HUFF = "828684410f7777772e6578616d706c652e636f6d"

CASES = {
    # --- RFC 7541 Appendix C -------------------------------------------
    "c31_first_request": [C_NO_HUFF],
    "c32_second_request": [C_NO_HUFF, "828684be58086e6f2d6361636865"],
    "c33_third_request": [
        C_NO_HUFF,
        "828684be58086e6f2d6361636865",
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    ],
    "c41_huffman_sequence": [
        C,
        "828684be5886a8eb10649cbf",
        "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
    ],
    # RFC 7541 C.5: responses under SETTINGS_HEADER_TABLE_SIZE = 256 show
    # the eviction order. :status-based blocks are rejected as requests
    # with h2_pseudo_missing, which both sides must agree on.
    "c5_responses_256": [
        "table 256",
        "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        "4803333037c1c0bf",
        "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
    ],
    "c6_huffman_responses_256": [
        "table 256",
        "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        "4883640effc1c0bf",
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
    ],

    # --- decoder rejections --------------------------------------------
    "index_zero": ["80"],
    "index_range_static_edge": ["be"],              # 62 with empty table
    "index_range_far": ["ff00"],
    "truncated_literal_name": ["400a637573746f6d2d6b6579"],
    "truncated_value": ["828684410f7777"],
    "truncated_integer": ["ffffffffffff7f"],
    "integer_overflow_exact": ["ffffffffffff0f"],
    "huffman_eos": ["41843fffffff"],
    "huffman_bad_padding": ["4182f1e3"],
    "huffman_truncated_code": ["4181ff"],
    "size_update_exceeds": ["3fe11f82"],            # 4096 + 1
    "size_update_after_field": ["8220"],
    "size_update_twice_ok": ["3fe01f3f0082"],
    "size_update_three": ["3fe01f3f0182"],

    # --- dynamic table management --------------------------------------
    "evict_oversized_entry": [
        "table 64",
        "3f01400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    ],
    "resize_to_zero": ["3f002082"],
    "resize_restore": ["3f003fe11f82"],
    "lower_settings_missing": [
        C_NO_HUFF,
        "table 128",
        "82",
    ],
    "lower_settings_acked": [
        C_NO_HUFF,
        "table 128",
        "3f6182",
    ],
    # Lowering the maximum and restoring it before the ack still requires
    # the smallest size in the interval (128) to be signalled first.
    "lower_then_raise_missing_min": [
        C_NO_HUFF,
        "table 128",
        "table 4096",
        "3fe11f82",
    ],
    "lower_then_raise_with_min": [
        C_NO_HUFF,
        "table 128",
        "table 4096",
        "3f213fe11f82",
    ],
    "duplicate_entry_reused": [
        "82868440066170706c69636174696f6e2f6a736f6e0b6170706c69636174696f6e",
        "82868440066170706c69636174696f6e2f6a736f6e0b6170706c69636174696f6e",
    ],

    # --- HTTP/2 field validation ---------------------------------------
    "uppercase_name": ["8286844005582d466f6f0176"],
    "invalid_name_space": ["8286844009782d746573742076616c"],
    "connection_header": ["828684400a636f6e6e656374696f6e05636c6f7365"],
    "transfer_encoding": [
        "82868440087472616e736665722d656e636f64696e67076368756e6b6564"
    ],
    "keep_alive": ["828684400a6b6565702d616c6976650135"],
    "upgrade": ["828684400775706772616465027431"],
    "te_trailers_ok": ["8286844002746508747261696c657273"],
    "te_other": ["8286844002746505677a6970"],
    "pseudo_after_regular": ["828684400875782d74657374017682"],
    "pseudo_dup": ["828284"],
    "pseudo_unknown": ["82868440073a6e6f737563680176"],
    "pseudo_missing_scheme": ["8284"],
    "path_relative": ["8286844001700176"],
    "path_asterisk_ok": ["82868440052a7b2a7d"],
    "value_leading_space": ["8286844001780120"],
    "value_trailing_space": ["828684402a780120"],
    "value_cr": ["828684400178010d"],
    "value_nul_tail": ["8286844001780100"],
    "cl_ok": ["828684400e636f6e74656e742d6c656e6774680135"],
    "cl_dup": [
        "828684400e636f6e74656e742d6c656e6774680135"
        "400e636f6e74656e742d6c656e6774680136"
    ],
    "cl_negative": ["828684400e636f6e74656e742d6c656e677468022d31"],
    "cl_overflow": ["828684400e636f6e74656e742d6c656e6774680a39393939393939393939"],
    "connect_ok": [
        "8386400a3a617574686f72697479096578616d706c653a343433"
    ],
    "connect_with_scheme": [
        "838684400a3a617574686f72697479096578616d706c653a343433"
    ],
    "connect_no_authority": ["83"],
    "regular_headers_kept": [
        "8286844112666f6f2d726571756573742d69640b313233343536373839"
    ],
    "huffman_in_name": [
        "828684418825a849e95ba97d7f408825a849e95bb8e8b4bf"
    ],
    "never_indexed_name": [
        "828684110d63616368652d636f6e74726f6c086e6f2d6361636865"
    ],
    "literal_no_index": ["828684440c2f73616d706c652f70617468"],

    # --- odd but legal integer encodings -------------------------------
    "index_62": ["be"],                             # with a seeded table
    "integer_long_zero_pad": ["8000"],
    "big_index": ["ffffff7f"],
}


def to_script(blocks):
    """Bare hex entries are field blocks; "table N" lines pass through."""
    lines = []
    for b in blocks:
        lines.append(b if b.startswith("table ") else "block " + b)
    return "\n".join(lines) + "\n"


def run(binary, script):
    if binary.endswith(".py"):
        argv = [sys.executable, "-I", binary]
    else:
        argv = [binary, "h2trace"]
    p = subprocess.run(argv, input=script, capture_output=True,
                       text=True)
    if p.returncode not in (0, 1):
        raise SystemExit("%s failed (%d):\n%s" % (binary, p.returncode, p.stderr))
    return p.stdout


def main():
    if not os.path.exists(BINARY):
        print("missing %s; run make first" % BINARY, file=sys.stderr)
        return 2

    failures = 0
    total = 0
    for name, blocks in CASES.items():
        script = to_script(blocks)
        total += 1
        ref = run(REF, script)
        got = run(BINARY, script)
        if ref == got:
            print("%s=1" % name)
        else:
            failures += 1
            print("%s=0" % name)
            ref_lines = ref.splitlines()
            got_lines = got.splitlines()
            for i in range(max(len(ref_lines), len(got_lines))):
                r = ref_lines[i] if i < len(ref_lines) else "<missing>"
                g = got_lines[i] if i < len(got_lines) else "<missing>"
                if r != g:
                    print("  line %d ref=%r got=%r" % (i, r, g))

    # RFC 7541 C.3.1 asserted against the literal expected header list.
    script = to_script([C_NO_HUFF])
    want = ("block 0\n"
            "field :method GET\n"
            "field :scheme http\n"
            "field :path /\n"
            "field :authority www.example.com\n"
            "result=ok\n"
            "table size=57 entries=1 max=4096\n")
    total += 1
    got = run(BINARY, script)
    if got == want:
        print("rfc_c31_literal=1")
    else:
        failures += 1
        print("rfc_c31_literal=0")
        print("  want=%r got=%r" % (want, got))

    print("crosscheck total=%d failed=%d" % (total, failures))
    print("crosscheck_ok=%d" % (1 if failures == 0 else 0))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
