# SPDX-License-Identifier: MIT
"""UDS over BLE on the PC side (blehost/protocols/uds.py and setu_client.py uds /
flash): the codecs against the golden frames of wire.json "uds_cmd" (the bytes the
C tests check on the firmware), the profile loader against the simulator's
profile, and UdsSession and the command line against FakeUdsDevice (conftest.py),
which answers with the firmware's rules and runs the flash sequence against the
ECU simulator."""

import asyncio
import json
import os
import struct

import pytest

import setu_client
from blehost.protocols import setu as proto
from blehost.protocols import uds
from conftest import REPO, FakeUdsDevice, FakeUdsSETU

SIM_PROFILE = os.path.join(REPO, "_TOOLS", "EcuSim", "profiles", "sim.json")
SIM_FD_PROFILE = os.path.join(REPO, "_TOOLS", "EcuSim", "profiles", "sim_fd.json")


def run(coro):
    return asyncio.run(coro)


def vec(vectors, name):
    return next(s for s in vectors["uds_cmd"]["shorts"] if s["name"] == name)


def payload(v) -> bytes:
    wire = bytes.fromhex(v["hex"])
    assert wire[0] == len(wire) - 2 and wire[1] == v["app_type"]
    return wire[2:]


def flash_file(vectors) -> bytes:
    return bytes.fromhex(vectors["uds_flash"]["file_hex"])


# ---- constants -------------------------------------------------------------------------
def test_constants_match_firmware(vectors):
    c = vectors["uds_cmd"]
    assert (uds.APP_TARGET, uds.APP_RESULT, uds.APP_DIAG_REQ, uds.APP_DIAG_RSP, uds.APP_UNLOCK, uds.APP_FLASH,
            uds.APP_STATUS, uds.APP_ABORT, uds.APP_STATUS_REQ) == tuple(c["app_types"].values())
    assert [uds.APP_FIRST, uds.APP_LAST] == c["app_type_range"]
    assert uds.STATUS == {v: k for k, v in c["status"].items()}
    assert uds.STATES == {v: k for k, v in c["states"].items()}
    assert uds.STEPS == {v: k for k, v in c["steps"].items()}
    assert uds.FF == c["flash_flags"]
    assert uds.ALGOS == c["algos"]
    assert (uds.TF_EXT_ID, uds.TF_FD, uds.TF_BRS, uds.TF_PAD, uds.TF_EXT_ADDR, uds.TF_FUNC) == tuple(
        c["target_flags"].values())
    lim = c["limits"]
    assert (uds.TARGET_LEN, uds.PARAMS_LEN, uds.STATUS_LEN, uds.FP_MAX, uds.NAME_MAX, uds.DIAG_REQ_MAX,
            uds.DIAG_PART_MAX) == (lim["target_len"], lim["params_len"], lim["status_len"], lim["fingerprint_max"],
                                   lim["name_max"], lim["diag_req_max"], lim["diag_part_max"])


# ---- codecs ----------------------------------------------------------------------------
def test_targets_encode_and_decode(vectors):
    for name in ("target_classic", "target_fd_29bit"):
        v = vec(vectors, name)
        t = uds.Target(tx_id=v["tx_id"], rx_id=v["rx_id"], func_id=v["func_id"] or None, bitrate=v["bitrate"],
                       fd=bool(v["flags"] & uds.TF_FD), data_bitrate=v["data_bitrate"],
                       brs=bool(v["flags"] & uds.TF_BRS), extended_ids=bool(v["flags"] & uds.TF_EXT_ID),
                       dl=v["dl"], padding=bool(v["flags"] & uds.TF_PAD), p2_ms=v["p2"], p2star_ms=v["p2star"])
        assert t.encode(v["seq"]) == payload(v), name
        assert uds.Target.decode(payload(v)) == (v["seq"], t)
    with pytest.raises(ValueError):
        uds.Target.decode(bytes(28))


def test_flash_params_and_requests_encode(vectors):
    c = vectors["uds_cmd"]
    sp = c["sim_params"]
    p = uds.FlashParams(flags=sp["flags"], security_level=sp["security_level"], key_algo=sp["key_algo"],
                        comm_control=sp["comm_control"], comm_type=sp["comm_type"], reset_type=sp["reset_type"],
                        alfid=sp["alfid"], dfi=sp["dfi"], erase_rid=sp["erase_rid"], check_rid=sp["check_rid"],
                        max_block=sp["max_block"], fingerprint_did=sp["fingerprint_did"],
                        fingerprint=bytes.fromhex(sp["fingerprint_hex"]))
    assert p.encode().hex() == c["sim_params_hex"]
    assert uds.FlashParams.decode(p.encode()) == p
    assert uds.encode_flash(11, p, "APP1.BIN") == payload(vec(vectors, "flash_app1"))
    assert uds.encode_diag(3, bytes.fromhex("22f190")) == payload(vec(vectors, "diag_req_vin"))
    assert uds.encode_diag(4, bytes.fromhex("3e00"), functional=True) == payload(vec(vectors, "diag_req_functional"))
    assert uds.encode_unlock(8, 1, uds.ALGOS["BENCH_XOR"]) == payload(vec(vectors, "unlock_l1"))
    assert bytes([13]) == payload(vec(vectors, "abort"))
    assert p.steps() == list(uds.FF)
    with pytest.raises(ValueError):
        uds.encode_flash(1, p, "")
    with pytest.raises(ValueError):
        uds.encode_flash(1, p, "N" * 33)
    with pytest.raises(ValueError):
        uds.encode_diag(1, b"")
    with pytest.raises(ValueError):
        uds.FlashParams(fingerprint=bytes(17)).encode()


def test_device_frames_decode(vectors):
    r = uds.decode_result(payload(vec(vectors, "result_unlock_nrc")))
    assert (r.seq, r.ref, r.status, r.data, r.ok) == (9, uds.APP_UNLOCK, uds.ST_NRC, b"\x35", False)
    d = uds.decode_diag_rsp(payload(vec(vectors, "diag_rsp_vin")))
    assert (d.seq, d.status, d.offset, d.data[3:]) == (3, 0, 0, vectors["uds_cmd"]["vin"].encode())
    st = uds.decode_status(payload(vec(vectors, "status_failed_nrc")))
    assert (st.state_name, st.step_name, st.last_nrc, st.running) == ("FAILED", "TRANSFER", 0x72, False)
    assert st.describe() == "FAILED TRANSFER record 2/2 20/30 bytes (66 %): NRC, SID 0x36 NRC 0x72"
    assert uds.decode_status(payload(vec(vectors, "status_running"))).describe() == \
        "RUNNING TRANSFER record 1/2 16/30 bytes (53 %)"
    for bad, fn in ((b"\x01\x02", uds.decode_result), (bytes(5), uds.decode_diag_rsp), (bytes(14), uds.decode_status)):
        with pytest.raises(ValueError):
            fn(bad)


def test_traffic_monitor_names_the_messages(vectors):
    for name, shown in (("target_classic", "seq=1 tx=0x7e0 rx=0x7e8 500k"),
                        ("result_unlock_nrc", "seq=9 UNLOCK NRC 35"),
                        ("diag_req_vin", "seq=3 22 f1 90"),
                        ("status_done", "DONE DONE record 2/2 30/30 bytes (100 %)")):
        v = vec(vectors, name)
        name_, decoder = proto._APP_TYPES[v["app_type"]]
        assert name_.startswith("UDS_")
        assert decoder(payload(v)) == shown, name


# ---- profile ---------------------------------------------------------------------------
def test_simulator_profile_is_the_vector_target_and_parameters(vectors):
    target, params = uds.load_profile(SIM_PROFILE)
    assert target.encode(1) == payload(vec(vectors, "target_classic"))
    assert params.encode().hex() == vectors["uds_cmd"]["sim_params_hex"]
    fd_target, fd_params = uds.load_profile(SIM_FD_PROFILE)
    assert (fd_target.fd, fd_target.brs, fd_target.dl) == (True, True, 64)
    assert fd_params == params


def test_profile_forms_and_minimal_flash():
    prof = {"addressing": {"tx_id": "0x18DA10F1", "rx_id": 0x18DAF110, "extended_ids": True},
            "can": {"fd": True}, "flash": {"security": {"level": 3, "algo": "0x80"}}}
    t, p = uds.load_profile(prof)
    assert (t.tx_id, t.extended_ids, t.dl, t.func_id, t.padding) == (0x18DA10F1, True, 64, None, True)
    assert (p.flags, p.security_level, p.key_algo) == (uds.FF["SECURITY"], 3, 0x80)
    t2, p2 = uds.load_profile(json.dumps({"addressing": {"tx_id": 1, "rx_id": 2}}))
    assert p2.flags == 0 and not t2.flags & uds.TF_FUNC


# ---- session ---------------------------------------------------------------------------
def test_session_target_diag_unlock(udsdev):
    s = uds.UdsSession(FakeUdsSETU(udsdev))
    target, _ = uds.load_profile(SIM_PROFILE)

    async def go():
        with pytest.raises(uds.UdsError, match="NOT_READY"):
            await s.unlock(1, 1)
        await s.target(target)
        st, rsp = await s.diag(bytes.fromhex("22f190"))
        assert (st, rsp) == (uds.ST_OK, b"\x62\xf1\x90" + b"WMI0HANUMAN000001")
        st, rsp = await s.diag(bytes.fromhex("22f1aa"))
        assert (st, rsp) == (uds.ST_NRC, b"\x7f\x22\x31")
        st, rsp = await s.diag(bytes.fromhex("3e80"))
        assert (st, rsp) == (uds.ST_OK, b"")
        # Unlocking needs a non-default session on the simulated ECU
        with pytest.raises(uds.UdsError, match=r"UNLOCK: NRC \(NRC 0x7f\)") as e:
            await s.unlock(1, uds.ALGOS["BENCH_XOR"])
        assert e.value.nrc == 0x7F
        await s.diag(bytes.fromhex("1003"))
        await s.unlock(1, uds.ALGOS["BENCH_XOR"])
        assert udsdev.ecu.unlocked
        with pytest.raises(uds.UdsError, match="NOT_SUPPORTED"):
            await s.unlock(1, 0x80)
        udsdev.target_status = 1
        with pytest.raises(uds.UdsError, match="TARGET: BUSY"):
            await s.target(target)
    run(go())


def test_session_reassembles_long_responses_and_skips_stale_frames(vectors, udsdev):
    setu = FakeUdsSETU(udsdev)
    s = uds.UdsSession(setu)
    long_rsp = bytes.fromhex(vectors["uds_cmd"]["long_response_hex"])
    udsdev.ecu.dtcs = [(i, 0xFF) for i in range((len(long_rsp) - 3) // 4)]

    async def go():
        await s.target(uds.load_profile(SIM_PROFILE)[0])
        setu.short_q.put_nowait((uds.APP_DIAG_RSP, struct.pack("<BBHH", 77, 0, 3, 0) + b"old"))   # stale
        st, rsp = await s.diag(bytes.fromhex("1902ff"))
        assert st == uds.ST_OK and len(rsp) == 3 + 4 * len(udsdev.ecu.dtcs)
        assert len(rsp) > uds.DIAG_PART_MAX, "came in parts"
        assert rsp[:3] == b"\x59\x02\xff"
    run(go())


def test_session_diag_timeout_and_device_silence(udsdev):
    setu = FakeUdsSETU(udsdev)
    s = uds.UdsSession(setu)

    async def go():
        await s.target(uds.load_profile(SIM_PROFILE)[0])
        udsdev.silent = True
        st, rsp = await s.diag(bytes.fromhex("22f190"))
        assert (st, rsp) == (6, b"")
        setu.device = None

        async def dead(app_type, payload):
            await asyncio.sleep(0)
        setu.send_short = dead
        with pytest.raises(uds.UdsError, match="no answer"):
            await s.diag(bytes.fromhex("22f190"), timeout=0.05)
    run(go())


def test_session_flashes_the_stored_file(vectors, udsdev):
    from ecu_sim import EcuSim
    udsdev.ecu = EcuSim(max_block=18)
    udsdev.files["APP1.BIN"] = flash_file(vectors)
    s = uds.UdsSession(FakeUdsSETU(udsdev))
    target, params = uds.load_profile(SIM_PROFILE)
    seen = []

    async def go():
        await s.target(target)
        return await s.flash("APP1.BIN", params, seen.append)
    st = run(go())
    assert (st.state_name, st.step_name, st.done, st.total, st.rec_cnt) == ("DONE", "DONE", 30, 30, 2)
    assert udsdev.ecu.image == flash_file(vectors)
    assert [x.step_name for x in seen][:4] == ["EXT_SESSION", "DTC_OFF", "COMM_OFF", "PROG_SESSION"]
    # The ECU saw the golden conversation's requests, in order
    assert [r.hex() for r in udsdev.ecu.requests] == [s_["req_hex"] for s_ in vectors["uds_flash"]["steps"]]


def test_session_flash_failures(vectors, udsdev):
    from ecu_sim import EcuSim
    s = uds.UdsSession(FakeUdsSETU(udsdev))
    target, params = uds.load_profile(SIM_PROFILE)

    async def go():
        with pytest.raises(uds.UdsError, match="FLASH: NOT_READY"):
            await s.flash("APP1.BIN", params)
        await s.target(target)
        with pytest.raises(uds.UdsError, match="FILE") as e:
            await s.flash("NOPE.BIN", params)
        assert e.value.status == 9
        udsdev.files["APP1.BIN"] = flash_file(vectors)
        udsdev.ecu = EcuSim(nrc_at=(0x36, 0x72))
        with pytest.raises(uds.UdsError, match="SID 0x36 NRC 0x72") as e:
            await s.flash("APP1.BIN", params)
        assert (e.value.status, e.value.nrc) == (uds.ST_NRC, 0x72)
        st = await s.status()
        assert st.state_name == "FAILED"
        with pytest.raises(uds.UdsError, match="ABORT: BAD_STATE"):
            await s.abort()
    run(go())


# ---- command line ----------------------------------------------------------------------
@pytest.fixture
def udscli(monkeypatch, udsdev):
    """setu_client.py with a fake bleak whose device is FakeUdsDevice."""
    import sys
    import types

    class Client:
        def __init__(self, target, disconnected_callback=None):
            self.cb = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        mtu_size = 247

        async def start_notify(self, uuid, cb):
            self.cb = cb

        async def write_gatt_char(self, uuid, data, response=False):
            data = bytes(data)                        # a short frame: [length][appType][payload]
            assert data[0] == len(data) - 2
            for rt, rp in udsdev.handle(data[1], data[2:]):
                self.cb(None, bytearray(setu_client.frame(rt, rp)))

    async def find(name, timeout=10.0):
        return "AA:BB"

    mod = types.ModuleType("bleak")
    mod.BleakClient = Client
    mod.BleakScanner = types.SimpleNamespace(find_device_by_name=find)
    monkeypatch.setitem(sys.modules, "bleak", mod)
    return udsdev


def cli(monkeypatch, *argv):
    import sys
    monkeypatch.setattr(sys, "argv", ["setu_client.py", *argv])
    asyncio.run(setu_client.main())


def test_cli_uds_and_flash(udscli, vectors, monkeypatch, capsys):
    from ecu_sim import EcuSim
    udscli.ecu = EcuSim(max_block=18)
    udscli.files["APP1.BIN"] = flash_file(vectors)
    cli(monkeypatch, "uds", "target", "--profile", SIM_PROFILE, "--name", "dev")
    cli(monkeypatch, "uds", "req", "22", "F190", "--name", "dev")
    cli(monkeypatch, "uds", "status", "--name", "dev")
    cli(monkeypatch, "flash", "APP1.BIN", "--profile", SIM_PROFILE, "--name", "dev")
    out = capsys.readouterr().out
    assert "target tx 0x7e0 rx 0x7e8, 500000 bit/s" in out
    assert "OK: 62 f1 90 57 4d 49" in out
    assert "IDLE NONE" in out
    assert "steps: EXT_SESSION, DTC_OFF" in out
    assert "DONE DONE record 2/2 30/30 bytes (100 %)" in out and "flashed APP1.BIN: 30 bytes" in out
    assert udscli.ecu.image == flash_file(vectors)


def test_cli_uds_errors(udscli, monkeypatch, capsys):
    with pytest.raises(SystemExit, match="uds: give a command"):
        cli(monkeypatch, "uds", "--name", "dev")
    with pytest.raises(SystemExit, match="flash NAME --profile PROFILE"):
        cli(monkeypatch, "flash", "APP1.BIN", "--name", "dev")
    with pytest.raises(SystemExit, match="uds: target needs --profile"):
        cli(monkeypatch, "uds", "target", "--name", "dev")
    with pytest.raises(SystemExit, match="uds: req HEX"):
        cli(monkeypatch, "uds", "req", "--name", "dev")
    with pytest.raises(SystemExit, match="uds: UNLOCK: NOT_READY"):
        cli(monkeypatch, "uds", "unlock", "--name", "dev")
    with pytest.raises(SystemExit, match="flash: FLASH: FILE|flash: flash NOPE"):
        cli(monkeypatch, "flash", "NOPE.BIN", "--profile", SIM_PROFILE, "--name", "dev")
    cli(monkeypatch, "uds", "req", "22F1AA", "--name", "dev")
    assert "NRC: 7f 22 31" in capsys.readouterr().out
