#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate wire_vectors.h for the C tests from _TEST/vectors/wire.json.

The hex-upload segment bytes are read from the repo's test .hex file with a
minimal Intel HEX reader of its own, deliberately independent of
setu_client.parse_ihex(), so the C end-to-end test does not inherit a bug
from the code the Python tests check.

    python gen_vectors.py <wire.json> <repo root> <out.h>
"""

import json
import os
import sys

KINDS = ("START", "DATA", "ACK", "NACK", "END", "ABORT", "SHORT")
FIELDS = {                                            # order of VEC_F[] per kind
    "START": ("xid", "app_type", "total_len", "chunk", "window", "crc32"),
    "DATA": ("xid", "seq"),
    "ACK": ("xid", "seq", "window"),
    "NACK": ("xid", "seq", "reason"),
    "END": ("xid", "status"),
    "ABORT": ("xid", "reason", "dir"),
    "SHORT": ("app_type",),
}


def read_ihex(path: str) -> dict:
    """Intel HEX -> {address: byte}. Types 00, 01, 02, 04; 03/05 ignored."""
    mem, upper, seg_wrap = {}, 0, False
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = bytes.fromhex(line[1:])
            assert line[0] == ":" and len(rec) == rec[0] + 5 and sum(rec) & 0xFF == 0, line
            addr, rtype, data = (rec[1] << 8) | rec[2], rec[3], rec[4:-1]
            if rtype == 0:
                for i, b in enumerate(data):
                    off = addr + i
                    mem[upper + ((off & 0xFFFF) if seg_wrap else off)] = b
            elif rtype == 1:
                break
            elif rtype == 2:                          # segment: offsets wrap at 64 KiB
                upper, seg_wrap = int.from_bytes(data, "big") << 4, True
            elif rtype == 4:
                upper, seg_wrap = int.from_bytes(data, "big") << 16, False
    return mem


def c_bytes(b: bytes, indent: str = "      ") -> str:
    if not b:
        return "0"
    rows = [", ".join(f"0x{x:02x}" for x in b[i:i + 12]) for i in range(0, len(b), 12)]
    return (",\n" + indent).join(rows)


def c_array(name: str, len_macro: str, b: bytes) -> str:
    """A const byte array (one dummy byte if b is empty: C has no empty arrays)."""
    return (f"#define {len_macro} ({len(b)}U)\n"
            f"static const uint8_t {name}[] =\n{{\n   {c_bytes(b or bytes(1), '   ')}\n}};\n")


def emit_provisioning(p: dict, o: list) -> None:
    """Device provisioning: appTypes, states, statuses, short frames and the CSR."""
    o.append("/* ---- Device provisioning (_DOC/Provisioning/PROTOCOL.md) ---- */")
    for group, prefix in (("app_types", "VEC_PROV_APP_"), ("states", "VEC_PROV_STATE_"),
                          ("status", "VEC_PROV_ST_"), ("flags", "VEC_PROV_FLAG_")):
        for name, val in p[group].items():
            o.append(f"#define {prefix}{name} ({val}U)")
    o.append(f"#define VEC_PROV_MAX_CERT_LEN ({p['max_cert_len']}U)\n")

    o.append("typedef struct\n{\n   const char *cpt_name;\n   uint8_t u8_appType;\n"
             "   uint8_t u8ar_wire[40];\n   uint8_t u8_wireLen;\n} ProvShortVector_T;\n")
    o.append("static const ProvShortVector_T gstar_vecProvShorts[] =\n{")
    for s in p["shorts"]:
        wire = bytes.fromhex(s["hex"])
        assert len(wire) <= 40 and wire[0] == len(wire) - 2 and wire[1] == s["app_type"], s["name"]
        o.append(f"   {{ \"{s['name']}\", {s['app_type']}U,\n"
                 f"      {{ {c_bytes(wire)} }}, {len(wire)}U }},")
    o.append("};\n")

    c = p["csr"]
    o.append(f"#define VEC_CSR_SUBJ_CNT ({len(c['subject'])}U)")
    o.append("static const char *const gcptar_vecCsrSubjName[] = { "
             + ", ".join(f"\"{n}\"" for n, _ in c["subject"]) + " };")
    o.append("static const char *const gcptar_vecCsrSubjValue[] = { "
             + ", ".join(f"\"{val}\"" for _, val in c["subject"]) + " };\n")
    for name, macro, key in (("gu8ar_vecCsrPubKey", "VEC_CSR_PUBKEY_LEN", "public_key"),
                             ("gu8ar_vecCsrSki", "VEC_CSR_SKI_LEN", "ski_sha1"),
                             ("gu8ar_vecCsrSig", "VEC_CSR_SIG_LEN", "signature_raw"),
                             ("gu8ar_vecCsrTbs", "VEC_CSR_TBS_LEN", "tbs"),
                             ("gu8ar_vecCsrDer", "VEC_CSR_DER_LEN", "der")):
        o.append(c_array(name, macro, bytes.fromhex(c[key])))


def uuid_le(text: str) -> bytes:
    """A UUID string as the 16 bytes Zephyr stores (BT_UUID_128_ENCODE: LSB first)."""
    return bytes.fromhex(text.replace("-", ""))[::-1]


def emit_pairing(p: dict, o: list) -> None:
    """Device pairing: constants, CONTROL and STATUS frames, the signed OOB frame."""
    o.append("/* ---- Device pairing (_DOC/Pairing/PROTOCOL.md) ---- */")
    for group, prefix in (("app_types", "VEC_PAIR_APP_"), ("ops", "VEC_PAIR_OP_"),
                          ("roles", "VEC_PAIR_ROLE_"), ("states", "VEC_PAIR_STATE_"),
                          ("errors", "VEC_PAIR_ERR_"), ("addr_types", "VEC_PAIR_ADDR_")):
        for name, val in p[group].items():
            o.append(f"#define {prefix}{name} ({val}U)")
    o.append(f"#define VEC_PAIR_APP_FIRST ({p['app_type_range'][0]}U)")
    o.append(f"#define VEC_PAIR_APP_LAST ({p['app_type_range'][1]}U)")
    for key in ("start_len", "status_len", "oob_frame_len", "oob_signed_len", "secured_value"):
        o.append(f"#define VEC_PAIR_{key.upper()} ({p[key]}U)")
    for name, text in p["uuids"].items():
        o.append(f"static const uint8_t gu8ar_vecPairUuid{name.capitalize()}[16] = "
                 f"{{ {c_bytes(uuid_le(text))} }};")
    o.append("")

    o.append("typedef struct\n{\n   const char *cpt_name;\n   uint8_t u8ar_wire[20];\n"
             "   uint8_t u8_wireLen;\n} PairVector_T;\n")
    for group, array in (("controls", "gstar_vecPairControls"), ("statuses", "gstar_vecPairStatuses")):
        o.append(f"static const PairVector_T {array}[] =\n{{")
        for c in p[group]:
            wire = bytes.fromhex(c["hex"])
            assert len(wire) <= 20, c["name"]
            o.append(f"   {{ \"{c['name']}\", {{ {c_bytes(wire)} }}, {len(wire)}U }},")
        o.append("};\n")

    for key, name in (("private_key", "PrivKey"), ("public_key", "PubKey"), ("r", "R"), ("c", "C"),
                      ("sender", "Sender"), ("receiver", "Receiver"), ("message", "Message"),
                      ("signature_raw", "Sig"), ("frame", "Frame")):
        o.append(c_array(f"gu8ar_vecPairOob{name}", f"VEC_PAIR_VEC_{name.upper()}_LEN",
                         bytes.fromhex(p["oob"][key])))


def emit_shorts(name: str, shorts: list, o: list) -> None:
    """A table of golden short frames [payload length][appType][payload]."""
    o.append(f"static const ShortVector_T {name}[] =\n{{")
    for s in shorts:
        wire = bytes.fromhex(s["hex"])
        assert wire[0] == len(wire) - 2 and wire[1] == s["app_type"], s["name"]
        o.append(f"   {{ \"{s['name']}\", {s['app_type']}U, {len(wire)}U,\n"
                 f"      {{ {c_bytes(wire)} }} }},")
    o.append("};\n")


def emit_file_system(hf: dict, fs: dict, o: list) -> None:
    """Hex upload stored as a file, and the BLE file commands."""
    o.append("/* ---- Short frames of the file features ---- */")
    o.append("typedef struct\n{\n   const char *cpt_name;\n   uint8_t u8_appType;\n"
             "   uint8_t u8_wireLen;\n   uint8_t u8ar_wire[244];\n} ShortVector_T;\n")

    o.append("/* ---- Hex upload stored as a file (_DOC/HexUpload/PROTOCOL.md) ---- */")
    for name, val in hf["app_types"].items():
        o.append(f"#define VEC_HEXF_APP_{name} ({val}U)")
    o.append(f"#define VEC_HEXF_DIR \"{hf['dir']}\"")
    o.append(f"#define VEC_HEXF_TEMP_NAME \"{hf['temp_name']}\"")
    o.append(f"#define VEC_HEXF_NAME_MAX ({hf['name_max']}U)")
    o.append(f"#define VEC_HEXF_FILE_REPLY_LEN ({hf['file_reply_len']}U)")
    r = hf["record"]
    o.append(f"#define VEC_HEXF_RECORD_ADDR ({r['address']}UL)")
    o.append(f"#define VEC_HEXF_RECORD_LEN ({r['length']}UL)")
    o.append(f"#define VEC_HEXF_FILE_SIZE ({r['file_size']}UL)")
    o.append(f"#define VEC_HEXF_FILE_CRC ({r['file_crc32']}UL)")
    o.append(f"static const uint8_t gu8ar_vecHexfRecordHdr[] = {{ {c_bytes(bytes.fromhex(r['header_hex']))} }};\n")
    emit_shorts("gstar_vecHexfShorts", hf["shorts"], o)

    o.append("/* ---- BLE file commands (_DOC/FileSysManager/PROTOCOL.md) ---- */")
    for group, prefix in (("app_types", "VEC_FS_APP_"), ("ops", "VEC_FS_OP_"),
                          ("status", "VEC_FS_ST_"), ("entry_types", "VEC_FS_ENTRY_")):
        for name, val in fs[group].items():
            o.append(f"#define {prefix}{name} ({val}U)")
    o.append(f"#define VEC_FS_APP_FIRST ({fs['app_type_range'][0]}U)")
    o.append(f"#define VEC_FS_APP_LAST ({fs['app_type_range'][1]}U)")
    for name, val in fs["limits"].items():
        o.append(f"#define VEC_FS_{name.upper()} ({val}U)")
    o.append("")
    emit_shorts("gstar_vecFsShorts", fs["shorts"], o)


def emit_uds(cmd: dict, key: dict, flash: dict, o: list) -> None:
    """UDS over BLE: constants, short frames, seed -> key cases, a flash conversation."""
    o.append("/* ---- UDS over BLE (_DOC/UDS/PROTOCOL.md) ---- */")
    for group, prefix in (("app_types", "VEC_UDS_APP_"), ("status", "VEC_UDS_ST_"),
                          ("states", "VEC_UDS_STATE_"), ("steps", "VEC_UDS_STEP_"),
                          ("target_flags", "VEC_UDS_TF_"), ("diag_flags", "VEC_UDS_DF_"),
                          ("flash_flags", "VEC_UDS_FF_"), ("algos", "VEC_UDS_ALGO_")):
        for name, val in cmd[group].items():
            o.append(f"#define {prefix}{name} ({val}U)")
    o.append(f"#define VEC_UDS_APP_FIRST ({cmd['app_type_range'][0]}U)")
    o.append(f"#define VEC_UDS_APP_LAST ({cmd['app_type_range'][1]}U)")
    for name, val in cmd["limits"].items():
        o.append(f"#define VEC_UDS_{name.upper()} ({val}U)")
    o.append(f"#define VEC_UDS_VIN \"{cmd['vin']}\"")
    o.append(c_array("gu8ar_vecUdsSimParams", "VEC_UDS_SIM_PARAMS_LEN", bytes.fromhex(cmd["sim_params_hex"])))
    o.append(c_array("gu8ar_vecUdsLongRsp", "VEC_UDS_LONG_RSP_LEN", bytes.fromhex(cmd["long_response_hex"])))
    emit_shorts("gstar_vecUdsShorts", cmd["shorts"], o)

    o.append("/* ---- Seed -> key (_ASW/_UDS/UdsKey.c) ---- */")
    o.append("typedef struct\n{\n   const char *cpt_name;\n   uint8_t u8_algo;\n   uint8_t u8_level;\n"
             "   uint8_t u8ar_seed[8];\n   uint8_t u8_seedLen;\n   uint8_t u8ar_key[8];\n"
             "   uint8_t u8_keyLen;\n} UdsKeyVector_T;\n")
    o.append("static const UdsKeyVector_T gstar_vecUdsKeys[] =\n{")
    for c in key["cases"]:
        seed, k = bytes.fromhex(c["seed_hex"]), bytes.fromhex(c["key_hex"])
        o.append(f"   {{ \"{c['name']}\", {c['algo']}U, {c['level']}U, {{ {c_bytes(seed)} }}, {len(seed)}U,\n"
                 f"      {{ {c_bytes(k)} }}, {len(k)}U }},")
    o.append("};\n")

    o.append("/* ---- A flash job's UDS conversation (_DOC/UDS/README.md) ---- */")
    o.append(f"#define VEC_UDS_IMAGE_CRC ({flash['image_crc32']}UL)")
    o.append(f"#define VEC_UDS_IMAGE_BYTES ({flash['image_bytes']}UL)")
    o.append(f"#define VEC_UDS_IMAGE_RECORDS ({len(flash['image'])}U)")
    o.append(f"#define VEC_UDS_MAX_BLOCK ({flash['max_block']}U)")
    o.append(c_array("gu8ar_vecUdsFile", "VEC_UDS_FILE_LEN", bytes.fromhex(flash["file_hex"])))
    o.append(c_array("gu8ar_vecUdsSeed", "VEC_UDS_SEED_LEN", bytes.fromhex(flash["seed_hex"])))
    o.append("typedef struct\n{\n   const char *cpt_name;\n   uint8_t u8ar_req[32];\n   uint8_t u8_reqLen;\n"
             "   uint8_t u8_rspCount;\n   uint8_t u8ar_rsp[2][16];\n   uint8_t u8ar_rspLen[2];\n} UdsStepVector_T;\n")
    o.append("static const UdsStepVector_T gstar_vecUdsSteps[] =\n{")
    for st in flash["steps"]:
        req = bytes.fromhex(st["req_hex"])
        rsps = [bytes.fromhex(r) for r in st["rsp_hex"]]
        assert len(req) <= 32 and 1 <= len(rsps) <= 2 and all(len(r) <= 16 for r in rsps), st["name"]
        rsp_c = ", ".join(f"{{ {c_bytes(r)} }}" for r in rsps)
        lens = ", ".join(f"{len(r)}U" for r in rsps)
        o.append(f"   {{ \"{st['name']}\", {{ {c_bytes(req)} }}, {len(req)}U, {len(rsps)}U,\n"
                 f"      {{ {rsp_c} }}, {{ {lens} }} }},")
    o.append("};\n")


def emit_host_auth(h: dict, o: list) -> None:
    """Host authentication: constants, short frames, one whole handshake."""
    o.append("/* ---- Host authentication (_DOC/HostAuth/PROTOCOL.md) ---- */")
    for group, prefix in (("app_types", "VEC_HAUTH_APP_"), ("states", "VEC_HAUTH_STATE_"),
                          ("flags", "VEC_HAUTH_FLAG_"), ("results", "VEC_HAUTH_RES_")):
        for name, val in h[group].items():
            o.append(f"#define {prefix}{name} ({val}U)")
    o.append(f"#define VEC_HAUTH_APP_FIRST ({h['app_type_range'][0]}U)")
    o.append(f"#define VEC_HAUTH_APP_LAST ({h['app_type_range'][1]}U)")
    for key in ("version", "nonce_len", "point_len", "sig_len", "hash_len", "hello_min_len",
                "challenge_header_len", "cert_max_len"):
        o.append(f"#define VEC_HAUTH_{key.upper()} ({h[key]}U)")
    o.append("")
    emit_shorts("gstar_vecHauthShorts", h["shorts"], o)

    adv = h["advert"]
    o.append(f"#define VEC_HAUTH_ADV_COMPANY_ID ({adv['company_id']}U)")
    o.append(f"#define VEC_HAUTH_ADV_FORMAT ({adv['format']}U)")
    for name, val in adv["flags"].items():
        o.append(f"#define VEC_HAUTH_ADV_FLAG_{name} ({val}U)")
    for fr in adv["frames"]:
        cname = "".join(w.capitalize() for w in fr["name"].split("_"))
        o.append(c_array(f"gu8ar_vecHauthAdv{cname}", f"VEC_HAUTH_ADV_{fr['name'].upper()}_LEN",
                         bytes.fromhex(fr["hex"])))

    hs = h["handshake"]
    o.append(f"#define VEC_HAUTH_PASSKEY ({hs['passkey']}UL)")
    for key, name in (("ca_cert", "CaCert"), ("device_cert", "DevCert"),
                      ("device_private_key", "DevPriv"), ("device_public_key", "DevPub"),
                      ("host_cert", "HostCert"), ("host_private_key", "HostPriv"),
                      ("host_public_key", "HostPub"), ("host_eph_private_key", "HostEphPriv"),
                      ("device_eph_private_key", "DevEphPriv"), ("nonce_host", "NonceHost"),
                      ("nonce_device", "NonceDev"), ("point_host", "PointHost"),
                      ("point_device", "PointDev"), ("transcript", "Transcript"),
                      ("secret", "Secret"), ("hkdf_output", "Hkdf"), ("sig_device", "SigDev"),
                      ("sig_host", "SigHost"), ("hello", "Hello"), ("challenge", "Challenge"),
                      ("finish", "Finish")):
        o.append(c_array(f"gu8ar_vecHauth{name}", f"VEC_HAUTH_{name.upper()}_LEN",
                         bytes.fromhex(hs[key])))


def main(json_path: str, root: str, out_path: str) -> None:
    with open(json_path) as f:
        v = json.load(f)

    o = []
    o.append("/* Generated by _TEST/tools/gen_vectors.py from _TEST/vectors/wire.json. Do not edit. */")
    o.append("#ifndef WIRE_VECTORS_H\n#define WIRE_VECTORS_H\n#include <stdint.h>\n")
    o.append(f"#define VEC_PROTOCOL_VERSION ({v['protocol_version']}U)")
    o.append(f"#define VEC_MAX_FRAME_LEN    ({v['max_frame_len']}U)")
    o.append(f"#define VEC_WINDOW           ({v['window']}U)")
    o.append(f"#define VEC_APP_TYPE_MAX     ({v['app_type_max']}U)")
    for group, prefix in (("frame_types", "VEC_T_"), ("status", "VEC_ST_"),
                          ("abort_dir", "VEC_DIR_"), ("hex_app_types", "VEC_APP_")):
        for name, val in v[group].items():
            o.append(f"#define {prefix}{name} ({val}U)")

    o.append("\ntypedef enum { " + ", ".join(f"eVK_{k}" for k in KINDS) + " } VecKind_E;")
    o.append("typedef struct\n{\n   const char *cpt_name;\n   VecKind_E e_kind;\n"
             "   uint32_t u32ar_f[6];          /* fields, order per kind in gen_vectors.py */\n"
             "   uint8_t u8ar_data[16];        /* DATA bytes / SHORT payload            */\n"
             "   uint8_t u8_dataLen;\n   uint8_t u8ar_wire[20];\n   uint8_t u8_wireLen;\n} WireVector_T;\n")
    o.append("static const WireVector_T gstar_vecFrames[] =\n{")
    for fr in v["frames"]:
        kind = fr["kind"]
        fields = ", ".join(f"{fr[k]}U" for k in FIELDS[kind]) or "0"
        data = bytes.fromhex(fr.get("data", fr.get("payload", "")))
        wire = bytes.fromhex(fr["hex"])
        o.append(f"   {{ \"{fr['name']}\", eVK_{kind}, {{ {fields} }},\n"
                 f"      {{ {c_bytes(data)} }}, {len(data)}U,\n"
                 f"      {{ {c_bytes(wire)} }}, {len(wire)}U }},")
    o.append("};\n")

    o.append("typedef struct\n{\n   const char *cpt_name;\n   uint8_t u8_appType;\n   uint8_t u8_status;\n"
             "   uint32_t u32_address;\n   uint32_t u32_length;\n   uint8_t u8ar_wire[11];\n} ReportVector_T;\n")
    o.append("static const ReportVector_T gstar_vecReports[] =\n{")
    for r in v["reports"]:
        wire = bytes.fromhex(r["hex"])
        o.append(f"   {{ \"{r['name']}\", {r['app_type']}U, {r['status']}U, {r['address']}UL, {r['length']}UL,\n"
                 f"      {{ {c_bytes(wire)} }} }},")
    o.append("};\n")

    o.append(f"static const uint8_t gu8ar_vecCaps[] = {{ {c_bytes(bytes.fromhex(v['caps']['hex']))} }};\n")

    hu = v["hex_upload"]
    mem = read_ihex(os.path.join(root, hu["file"]))
    seg = hu["segments"][0]
    data = bytes(mem[a] for a in range(seg["address"], seg["address"] + seg["length"]))
    start = next(i for i, fr in enumerate(v["frames"]) if fr["name"] == hu["start_frame"])
    o.append(f"/* First segment of {hu['file']} */")
    o.append(f"#define VEC_HEX_SEG_ADDR     ({seg['address']}UL)")
    o.append(f"#define VEC_HEX_SEG_LEN      ({seg['length']}UL)")
    o.append(f"#define VEC_HEX_START_IDX    ({start}U)")
    o.append(f"#define VEC_HEX_SEG_LINE     \"{hu['seg_line']}\"")
    o.append(f"static const uint8_t gu8ar_vecHexSeg[VEC_HEX_SEG_LEN] =\n{{\n   {c_bytes(data, '   ')}\n}};\n")

    emit_provisioning(v["provisioning"], o)
    emit_pairing(v["pairing"], o)
    emit_file_system(v["hex_file"], v["file_system"], o)
    emit_uds(v["uds_cmd"], v["uds_key"], v["uds_flash"], o)
    emit_host_auth(v["host_auth"], o)
    o.append("#endif /* WIRE_VECTORS_H */\n")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(o))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
