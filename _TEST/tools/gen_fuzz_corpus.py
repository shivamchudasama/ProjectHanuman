#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write seed corpora for the fuzz targets in _TEST/fuzz from vectors/wire.json.

    python gen_fuzz_corpus.py <wire.json> <out_dir>

Writes <out_dir>/setu_rx/*: scripts for fuzz_setu_rx (see its file header for
the opcodes): each golden frame and short message alone, a whole valid hex
upload, and BEGIN + upload + COMMIT.
"""

import json
import os
import struct
import sys
import zlib

OP_WRITE, OP_SETTLE, OP_DUMP = 0x00, 0x04, 0x05
T_START, T_DATA = 0xF0, 0xF1
CHUNK = 240


def op_write(frame: bytes) -> bytes:
    assert 1 <= len(frame) <= 244
    return bytes([OP_WRITE, len(frame) % 244]) + frame


def frame(ftype: int, payload: bytes) -> bytes:
    return bytes([len(payload), ftype]) + payload


def upload(app_type: int, obj: bytes, xid: int = 1) -> bytes:
    """A whole transfer as the reference client sends it (one window)."""
    crc = zlib.crc32(obj) & 0xFFFFFFFF
    out = op_write(frame(T_START, struct.pack("<BBIBBI", xid, app_type, len(obj), CHUNK, 16, crc)))
    out += bytes([OP_SETTLE, 5])
    for seq, off in enumerate(range(0, len(obj), CHUNK)):
        out += op_write(frame(T_DATA, bytes([xid, seq & 0xFF]) + obj[off:off + CHUNK]))
    return out + bytes([OP_SETTLE, 20])


def main() -> None:
    wire, out_dir = sys.argv[1], sys.argv[2]
    vec = json.load(open(wire))
    seeds = {}

    for f in vec["frames"]:
        seeds[f"frame_{f['name']}"] = op_write(bytes.fromhex(f["hex"].replace(" ", "")))
    for section in ("hex_file", "file_system", "provisioning"):
        for s in vec[section].get("shorts", []):
            seeds[f"{section}_{s['name']}"] = op_write(bytes.fromhex(s["hex"].replace(" ", "")))

    seg = struct.pack("<I", 0x00010000) + bytes(range(256)) * 2
    seeds["upload_segment"] = upload(0x10, seg) + bytes([OP_DUMP, OP_SETTLE, 20])
    shorts = {s["name"]: bytes.fromhex(s["hex"]) for s in vec["hex_file"]["shorts"]}
    seeds["begin_upload_commit"] = (op_write(shorts["begin_fw1"]) + bytes([OP_SETTLE, 5, OP_DUMP])
                                    + upload(0x10, seg) + bytes([OP_DUMP, OP_SETTLE, 5])
                                    + op_write(shorts["commit"]) + bytes([OP_SETTLE, 5, OP_DUMP]))

    write_dir(out_dir, "setu_rx", seeds)

    # fuzz_fscmd: [0][len][payload] per host CMD, then all of them in one run
    fs = {s["name"]: bytes.fromhex(s["hex"]) for s in vec["file_system"]["shorts"]
          if s["app_type"] == vec["file_system"]["app_types"]["CMD"]}
    seeds = {n: bytes([0, w[0]]) + w[2:2 + w[0]] for n, w in fs.items()}
    seeds["all_cmds"] = b"".join(seeds.values())
    write_dir(out_dir, "fscmd", seeds)

    # fuzz_uds_cmd: [0][type - 0x50][len][payload] per host message, a job end
    # with a long response, and the whole vector conversation
    host = (0x50, 0x52, 0x54, 0x55, 0x57, 0x58)
    uds = {s["name"]: bytes.fromhex(s["hex"]) for s in vec["uds_cmd"]["shorts"] if s["app_type"] in host}
    seeds = {n: bytes([0, w[1] - 0x50, w[0]]) + w[2:2 + w[0]] for n, w in uds.items()}
    rsp = bytes.fromhex(vec["uds_cmd"]["long_response_hex"])
    seeds["diag_long_rsp"] = seeds["diag_req_vin"] + bytes([2, 0]) + struct.pack("<H", len(rsp)) + rsp
    seeds["all_msgs"] = b"".join(seeds.values())
    write_dir(out_dir, "uds_cmd", seeds)

    # fuzz_uds_job: [flags][level][algo][alfid][dfi][max block][fp len] + the file
    p = bytes.fromhex(vec["uds_cmd"]["sim_params_hex"])
    file_ = bytes.fromhex(vec["uds_flash"]["file_hex"])
    for name, flags, max_block in (("sim", p[0:2], 0x0FFA), ("all", b"\xff\xff", 0x0012),
                                   ("none", b"\x00\x00", 0x0102)):
        hdr = flags + bytes([p[2], p[3], p[7], p[8]]) + struct.pack("<H", max_block) + bytes([7])
        seeds = {f"flash_{name}": hdr + file_,
                 f"flash_{name}_cut": hdr + file_[:len(file_) // 2],
                 f"flash_{name}_two": hdr + file_ + file_}
        write_dir(out_dir, "uds_job", seeds)

    # fuzz_host_auth: connect, the vector HELLO, FINISH, then pairing at level 4
    ha = vec["host_auth"]
    hello = bytes.fromhex(ha["handshake"]["hello"])
    finish = bytes.fromhex(ha["handshake"]["finish"])
    op_hello = bytes([2]) + struct.pack("<H", len(hello)) + b"\xff" + hello
    op_finish = bytes([3, finish[1] - 0x60, finish[0]]) + finish[2:]
    seeds = {
        "handshake": bytes([0]) + op_hello + op_finish + bytes([5, 0x07, 4, 4, 0]),
        "handshake_then_drop": bytes([0]) + op_hello + op_finish + bytes([5, 0x07, 1, 6, 1, 7, 200]),
        "status_req": bytes([0, 3, 0, 0]),
        "window_and_timeout": bytes([6, 0, 0]) + op_hello + bytes([7, 70, 7, 200]),
    }
    write_dir(out_dir, "host_auth", seeds)


def write_dir(out_dir: str, name: str, seeds: dict) -> None:
    d = os.path.join(out_dir, name)
    os.makedirs(d, exist_ok=True)
    for seed, data in seeds.items():
        with open(os.path.join(d, seed), "wb") as fh:
            fh.write(data)
    print(f"{len(seeds)} seeds in {d}")


if __name__ == "__main__":
    main()
