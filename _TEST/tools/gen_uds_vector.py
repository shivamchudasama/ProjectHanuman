#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write the "uds_cmd", "uds_key" and "uds_flash" sections of _TEST/vectors/wire.json.

uds_cmd    The BLE messages that drive UDS on the device (_DOC/UDS/PROTOCOL.md):
           appTypes 0x50-0x58, status codes, flash states and steps, flag bits,
           and golden short frames [payload length][appType][payload].
uds_key    Seed -> key vectors of the on-device algorithms (_ASW/_UDS/UdsKey.c);
           the ECU simulator (_TOOLS/EcuSim) implements the same BENCH_XOR.
uds_flash  The UDS conversation of a flash job (_DOC/UDS/README.md): a two-record
           image, the job parameters of the simulator's profile, and every
           request with the responses the ECU gives (one NRC 0x78 included).
           The C flasher test plays the ECU side of it, the simulator test the
           tester side, so firmware and simulator cannot drift apart.

Run after a change to any of these formats, then rebuild the tests:

    python _TEST/tools/gen_uds_vector.py

Only these three sections are replaced (see wire_section.py).
"""

import struct
import zlib

from wire_section import replace_section

SHORT_MAX = 242                                       # SETU short payload

APP = {"TARGET": 0x50, "RESULT": 0x51, "DIAG_REQ": 0x52, "DIAG_RSP": 0x53, "UNLOCK": 0x54,
       "FLASH": 0x55, "STATUS": 0x56, "ABORT": 0x57, "STATUS_REQ": 0x58}

# UdsCmdStatus_E (_ASW/_UDS/UdsCmd.h)
STATUS = {"OK": 0, "BUSY": 1, "BAD_ARG": 2, "BAD_STATE": 3, "NOT_READY": 4, "NRC": 5,
          "TIMEOUT": 6, "TRANSPORT": 7, "BUS_OFF": 8, "FILE": 9, "ABORTED": 10,
          "NOT_SUPPORTED": 11}

# UdsJobState_E / UdsJobStep_E (_ASW/_UDS/UdsJob.h)
STATES = {"IDLE": 0, "RUNNING": 1, "DONE": 2, "FAILED": 3, "ABORTED": 4}
STEPS = {"NONE": 0, "EXT_SESSION": 1, "DTC_OFF": 2, "COMM_OFF": 3, "PROG_SESSION": 4,
         "SECURITY": 5, "FINGERPRINT": 6, "ERASE": 7, "DOWNLOAD": 8, "TRANSFER": 9,
         "EXIT": 10, "CHECK": 11, "RESET": 12, "DONE": 13}

TARGET_FLAGS = {"EXT_ID": 0x01, "FD": 0x02, "BRS": 0x04, "PAD": 0x08, "EXT_ADDR": 0x10,
                "FUNC": 0x20}
DIAG_FLAGS = {"FUNCTIONAL": 0x01}
FLASH_FLAGS = {"EXT_SESSION": 0x0001, "DTC_OFF": 0x0002, "COMM_OFF": 0x0004, "SECURITY": 0x0008,
               "FINGERPRINT": 0x0010, "ERASE": 0x0020, "ERASE_PER_RECORD": 0x0040,
               "CHECK": 0x0080, "CHECK_CRC": 0x0100, "RESET": 0x0200}

FP_MAX = 16
NAME_MAX = 32
TARGET_LEN = 29                                       # TARGET payload
PARAMS_LEN = 34                                       # UdsFlashParams_T on the wire
STATUS_LEN = 15                                       # STATUS payload
DIAG_REQ_MAX = SHORT_MAX - 2                          # [seq][flags][request]
DIAG_PART_MAX = SHORT_MAX - 6                         # [seq][status][u16 total][u16 offset][data]

# Algorithm 1, BENCH_XOR: bench only, not secure
BENCH_MASK = (0x5A, 0xA5, 0x3C, 0xC3)
ALGOS = {"NONE": 0x00, "BENCH_XOR": 0x01}


def bench_xor(level: int, seed: bytes) -> bytes:
    out = bytearray()
    for i, s in enumerate(seed):
        v = s ^ BENCH_MASK[i & 3] ^ level
        out.append(((v << 1) | (v >> 7)) & 0xFF)
    return bytes(out)


def short(name: str, app: str, payload: bytes, **fields) -> dict:
    assert len(payload) <= SHORT_MAX, name
    entry = {"name": name, "app_type": APP[app]}
    entry.update(fields)
    entry["hex"] = (bytes([len(payload), APP[app]]) + payload).hex()
    return entry


# ---- Target ------------------------------------------------------------------
def target_payload(seq, flags, bitrate, data_bitrate, tx_id, rx_id, func_id, ext_addr, dl, pad,
                   p2, p2star) -> bytes:
    p = struct.pack("<BBIIIIIBBBHH", seq, flags, bitrate, data_bitrate, tx_id, rx_id, func_id,
                    ext_addr, dl, pad, p2, p2star)
    assert len(p) == TARGET_LEN
    return p


# ---- Flash job parameters ----------------------------------------------------
SIM_PARAMS = {
    "flags": (FLASH_FLAGS["EXT_SESSION"] | FLASH_FLAGS["DTC_OFF"] | FLASH_FLAGS["COMM_OFF"]
              | FLASH_FLAGS["SECURITY"] | FLASH_FLAGS["FINGERPRINT"] | FLASH_FLAGS["ERASE"]
              | FLASH_FLAGS["ERASE_PER_RECORD"] | FLASH_FLAGS["CHECK"] | FLASH_FLAGS["CHECK_CRC"]
              | FLASH_FLAGS["RESET"]),
    "security_level": 1, "key_algo": ALGOS["BENCH_XOR"],
    "comm_control": 0x03, "comm_type": 0x01, "reset_type": 0x01,
    "alfid": 0x44, "dfi": 0x00,
    "erase_rid": 0xFF00, "check_rid": 0xFF01, "max_block": 0,
    "fingerprint_did": 0xF15A, "fingerprint_hex": "20261012010203",
}


def params_payload(p: dict) -> bytes:
    fp = bytes.fromhex(p["fingerprint_hex"])
    assert len(fp) <= FP_MAX
    b = struct.pack("<HBBBBBBBHHHHB", p["flags"], p["security_level"], p["key_algo"],
                    p["comm_control"], p["comm_type"], p["reset_type"], p["alfid"], p["dfi"],
                    p["erase_rid"], p["check_rid"], p["max_block"], p["fingerprint_did"], len(fp))
    b += fp + bytes(FP_MAX - len(fp))
    assert len(b) == PARAMS_LEN
    return b


def flash_payload(seq: int, p: dict, name: str) -> bytes:
    n = name.encode()
    assert 1 <= len(n) <= NAME_MAX
    return bytes([seq]) + params_payload(p) + bytes([len(n)]) + n


def status_payload(state, step, rec_idx, rec_cnt, done, total, sid, nrc, status) -> bytes:
    p = struct.pack("<BBBBIIBBB", STATES[state], STEPS[step], rec_idx, rec_cnt, done, total, sid,
                    nrc, STATUS[status])
    assert len(p) == STATUS_LEN
    return p


def result(name, seq, ref, status, data=b""):
    return short(name, "RESULT", bytes([seq, APP[ref], STATUS[status]]) + data, seq=seq,
                 ref=APP[ref], status=STATUS[status], data_hex=data.hex())


def diag_rsp(name, seq, status, total, offset, data=b""):
    return short(name, "DIAG_RSP", struct.pack("<BBHH", seq, STATUS[status], total, offset) + data,
                 seq=seq, status=STATUS[status], total=total, offset=offset, data_hex=data.hex())


def uds_cmd_section() -> dict:
    vin = b"WMI0HANUMAN000001"
    long_rsp = bytes([0x59, 0x02, 0xFF]) + bytes((i * 7) & 0xFF for i in range(297))   # 300 bytes
    return {
        "_comment": [
            "BLE messages for UDS (_DOC/UDS/PROTOCOL.md), SETU short messages on the host link.",
            "TARGET [seq][flags][u32 bitrate][u32 data bitrate][u32 tx id][u32 rx id][u32 func id]",
            "[ext addr][tx dl][pad byte][u16 P2 ms][u16 P2* ms]; RESULT [seq][ref appType][status]",
            "[data]; DIAG_REQ [seq][flags][request]; DIAG_RSP [seq][status][u16 total][u16 offset]",
            "[part]; UNLOCK [seq][level][algo]; FLASH [seq][params][u8 name len][name]; STATUS",
            "[state][step][rec idx][rec cnt][u32 done][u32 total][last SID][last NRC][status];",
            "ABORT, STATUS_REQ [seq]. Numbers little-endian. Written by _TEST/tools/gen_uds_vector.py."
        ],
        "app_types": APP,
        "app_type_range": [0x50, 0x5F],
        "status": STATUS,
        "states": STATES,
        "steps": STEPS,
        "target_flags": TARGET_FLAGS,
        "diag_flags": DIAG_FLAGS,
        "flash_flags": FLASH_FLAGS,
        "algos": ALGOS,
        "limits": {"target_len": TARGET_LEN, "params_len": PARAMS_LEN, "status_len": STATUS_LEN,
                   "fingerprint_max": FP_MAX, "name_max": NAME_MAX, "diag_req_max": DIAG_REQ_MAX,
                   "diag_part_max": DIAG_PART_MAX},
        "sim_params": SIM_PARAMS,
        "sim_params_hex": params_payload(SIM_PARAMS).hex(),
        "vin": vin.decode(),
        "long_response_hex": long_rsp.hex(),
        "shorts": [
            short("target_classic", "TARGET",
                  target_payload(1, TARGET_FLAGS["PAD"] | TARGET_FLAGS["FUNC"], 500000, 0, 0x7E0,
                                 0x7E8, 0x7DF, 0, 8, 0xCC, 0, 0),
                  seq=1, flags=TARGET_FLAGS["PAD"] | TARGET_FLAGS["FUNC"], bitrate=500000,
                  data_bitrate=0, tx_id=0x7E0, rx_id=0x7E8, func_id=0x7DF, ext_addr=0, dl=8,
                  pad=0xCC, p2=0, p2star=0),
            short("target_fd_29bit", "TARGET",
                  target_payload(2, TARGET_FLAGS["EXT_ID"] | TARGET_FLAGS["FD"] | TARGET_FLAGS["BRS"]
                                 | TARGET_FLAGS["PAD"], 500000, 2000000, 0x18DA10F1, 0x18DAF110, 0,
                                 0, 64, 0xAA, 100, 6000),
                  seq=2, flags=TARGET_FLAGS["EXT_ID"] | TARGET_FLAGS["FD"] | TARGET_FLAGS["BRS"]
                  | TARGET_FLAGS["PAD"], bitrate=500000, data_bitrate=2000000, tx_id=0x18DA10F1,
                  rx_id=0x18DAF110, func_id=0, ext_addr=0, dl=64, pad=0xAA, p2=100, p2star=6000),
            result("result_target_ok", 1, "TARGET", "OK"),
            result("result_target_busy", 2, "TARGET", "BUSY"),
            short("diag_req_vin", "DIAG_REQ", bytes([3, 0, 0x22, 0xF1, 0x90]), seq=3, flags=0,
                  request_hex="22f190"),
            short("diag_req_functional", "DIAG_REQ", bytes([4, DIAG_FLAGS["FUNCTIONAL"], 0x3E, 0x00]),
                  seq=4, flags=DIAG_FLAGS["FUNCTIONAL"], request_hex="3e00"),
            diag_rsp("diag_rsp_vin", 3, "OK", 3 + len(vin), 0, b"\x62\xF1\x90" + vin),
            diag_rsp("diag_rsp_nrc", 5, "NRC", 3, 0, bytes([0x7F, 0x22, 0x31])),
            diag_rsp("diag_rsp_timeout", 6, "TIMEOUT", 0, 0),
            diag_rsp("diag_rsp_suppressed", 4, "OK", 0, 0),
            diag_rsp("diag_rsp_long_part0", 7, "OK", len(long_rsp), 0, long_rsp[:DIAG_PART_MAX]),
            diag_rsp("diag_rsp_long_part1", 7, "OK", len(long_rsp), DIAG_PART_MAX,
                     long_rsp[DIAG_PART_MAX:]),
            short("unlock_l1", "UNLOCK", bytes([8, 1, ALGOS["BENCH_XOR"]]), seq=8, level=1,
                  algo=ALGOS["BENCH_XOR"]),
            result("result_unlock_ok", 8, "UNLOCK", "OK"),
            result("result_unlock_nrc", 9, "UNLOCK", "NRC", bytes([0x35])),
            result("result_unlock_unknown_algo", 10, "UNLOCK", "NOT_SUPPORTED"),
            short("flash_app1", "FLASH", flash_payload(11, SIM_PARAMS, "APP1.BIN"), seq=11,
                  file="APP1.BIN"),
            result("result_flash_ok", 11, "FLASH", "OK"),
            result("result_flash_not_ready", 12, "FLASH", "NOT_READY"),
            short("status_running", "STATUS",
                  status_payload("RUNNING", "TRANSFER", 0, 2, 16, 30, 0x36, 0, "OK"),
                  state=STATES["RUNNING"], step=STEPS["TRANSFER"], rec_idx=0, rec_cnt=2, done=16,
                  total=30, last_sid=0x36, last_nrc=0, status=STATUS["OK"]),
            short("status_done", "STATUS",
                  status_payload("DONE", "DONE", 2, 2, 30, 30, 0x11, 0, "OK"),
                  state=STATES["DONE"], step=STEPS["DONE"], rec_idx=2, rec_cnt=2, done=30, total=30,
                  last_sid=0x11, last_nrc=0, status=STATUS["OK"]),
            short("status_failed_nrc", "STATUS",
                  status_payload("FAILED", "TRANSFER", 1, 2, 20, 30, 0x36, 0x72, "NRC"),
                  state=STATES["FAILED"], step=STEPS["TRANSFER"], rec_idx=1, rec_cnt=2, done=20,
                  total=30, last_sid=0x36, last_nrc=0x72, status=STATUS["NRC"]),
            short("status_idle", "STATUS",
                  status_payload("IDLE", "NONE", 0, 0, 0, 0, 0, 0, "OK"),
                  state=STATES["IDLE"], step=STEPS["NONE"], rec_idx=0, rec_cnt=0, done=0, total=0,
                  last_sid=0, last_nrc=0, status=STATUS["OK"]),
            short("abort", "ABORT", bytes([13]), seq=13),
            result("result_abort_ok", 13, "ABORT", "OK"),
            short("status_req", "STATUS_REQ", bytes([14]), seq=14),
        ],
    }


# ---- Seed -> key -------------------------------------------------------------
def uds_key_section() -> dict:
    cases = []
    for name, level, seed in (("l1_4byte", 1, bytes.fromhex("11223344")),
                              ("l3_4byte", 3, bytes.fromhex("deadbeef")),
                              ("l1_2byte", 1, bytes.fromhex("0001")),
                              ("l5_8byte", 5, bytes.fromhex("0123456789abcdef"))):
        cases.append({"name": name, "algo": ALGOS["BENCH_XOR"], "level": level, "seed_hex": seed.hex(),
                      "key_hex": bench_xor(level, seed).hex()})
    return {
        "_comment": [
            "Seed -> key (_ASW/_UDS/UdsKey.c). BENCH_XOR (algo 1), for the bench only:",
            "key[i] = rotl8(seed[i] ^ mask[i % 4] ^ level, 1), mask = 5A A5 3C C3; the key is",
            "as long as the seed. Algorithms 0x80-0xFF are OEM ones (not in the repository).",
            "Written by _TEST/tools/gen_uds_vector.py."
        ],
        "mask_hex": bytes(BENCH_MASK).hex(),
        "cases": cases,
    }


# ---- Flash conversation ------------------------------------------------------
IMAGE = [(0x00008000, bytes(range(0x10, 0x10 + 20))), (0x00010000, bytes(range(0xA0, 0xA0 + 10)))]
SIM_SEED = bytes.fromhex("11223344")
SIM_MAX_BLOCK = 18                                    # 16 data bytes per TransferData
SESSION_TIMING = bytes([0x00, 0x32, 0x01, 0xF4])      # P2 50 ms, P2* 500 x 10 ms


def flash_conversation(p: dict) -> list:
    steps = []

    def step(name, req, *rsps):
        steps.append({"name": name, "req_hex": bytes(req).hex(), "rsp_hex": [bytes(r).hex() for r in rsps]})

    image_crc = 0
    for _, data in IMAGE:
        image_crc = zlib.crc32(data, image_crc)
    image_crc &= 0xFFFFFFFF

    step("ext_session", [0x10, 0x03], [0x50, 0x03] + list(SESSION_TIMING))
    step("dtc_off", [0x85, 0x02], [0xC5, 0x02])
    step("comm_off", [0x28, p["comm_control"], p["comm_type"]], [0x68, p["comm_control"]])
    step("prog_session", [0x10, 0x02], [0x7F, 0x10, 0x78], [0x50, 0x02] + list(SESSION_TIMING))
    step("seed", [0x27, p["security_level"]], [0x67, p["security_level"]] + list(SIM_SEED))
    key = bench_xor(p["security_level"], SIM_SEED)
    step("key", [0x27, p["security_level"] + 1] + list(key), [0x67, p["security_level"] + 1])
    did = p["fingerprint_did"]
    step("fingerprint", [0x2E, did >> 8, did & 0xFF] + list(bytes.fromhex(p["fingerprint_hex"])),
         [0x6E, did >> 8, did & 0xFF])
    erase = p["erase_rid"]
    for idx, (addr, data) in enumerate(IMAGE):
        al = struct.pack(">II", addr, len(data))
        step(f"erase_{idx}", [0x31, 0x01, erase >> 8, erase & 0xFF, p["alfid"]] + list(al),
             [0x71, 0x01, erase >> 8, erase & 0xFF, 0x00])
        step(f"download_{idx}", [0x34, p["dfi"], p["alfid"]] + list(al),
             [0x74, 0x20, SIM_MAX_BLOCK >> 8, SIM_MAX_BLOCK & 0xFF])
        bsc = 1
        for off in range(0, len(data), SIM_MAX_BLOCK - 2):
            block = data[off:off + SIM_MAX_BLOCK - 2]
            step(f"transfer_{idx}_{bsc}", [0x36, bsc] + list(block), [0x76, bsc])
            bsc = (bsc + 1) & 0xFF
        step(f"exit_{idx}", [0x37], [0x77])
    chk = p["check_rid"]
    step("check", [0x31, 0x01, chk >> 8, chk & 0xFF] + list(struct.pack(">I", image_crc)),
         [0x71, 0x01, chk >> 8, chk & 0xFF, 0x00])
    step("reset", [0x11, p["reset_type"]], [0x51, p["reset_type"]])
    return steps, image_crc


def uds_flash_section() -> dict:
    steps, image_crc = flash_conversation(SIM_PARAMS)
    file_bytes = b"".join(struct.pack("<II", a, len(d)) + d for a, d in IMAGE)
    return {
        "_comment": [
            "A flash job's UDS conversation (_DOC/UDS/README.md) with the simulator's",
            "parameters (uds_cmd.sim_params): the stored file holds the two records, the",
            "ECU's RequestDownload answer allows 18-byte blocks (16 data bytes), and the",
            "programming session is answered with one NRC 0x78 first. Every step is a request",
            "and the ECU's responses in order. The check routine carries the CRC-32 (IEEE,",
            "big-endian) of the records' data. Written by _TEST/tools/gen_uds_vector.py."
        ],
        "image": [{"address": a, "data_hex": d.hex()} for a, d in IMAGE],
        "file_hex": file_bytes.hex(),
        "image_crc32": image_crc,
        "image_bytes": sum(len(d) for _, d in IMAGE),
        "seed_hex": SIM_SEED.hex(),
        "max_block": SIM_MAX_BLOCK,
        "steps": steps,
    }


def main() -> None:
    replace_section("uds_cmd", uds_cmd_section())
    replace_section("uds_key", uds_key_section())
    replace_section("uds_flash", uds_flash_section())
    print("uds_cmd, uds_key and uds_flash vectors written")


if __name__ == "__main__":
    main()
