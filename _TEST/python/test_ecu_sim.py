# SPDX-License-Identifier: MIT
"""The UDS ECU simulator (_TOOLS/EcuSim/ecu_sim.py): the uds_flash conversation of
wire.json replayed request by request (the firmware's flasher test plays the other
side of the same conversation), BENCH_XOR against the uds_key vectors, every
service and refusal, the fault injection, and the simulator on a python-can
virtual bus with can-isotp (classic and CAN FD), as on the bench."""

import threading
import time

import pytest

import ecu_sim
from ecu_sim import EcuSim


def answers(sim, hex_req, functional=False):
    """The responses (without the delays) to a request given in hex."""
    return [r.hex() for _, r in sim.handle(bytes.fromhex(hex_req), functional)]


def unlocked(sim):
    """Programming session, unlocked."""
    answers(sim, "1002")
    seed = bytes.fromhex(answers(sim, "2701")[0])[2:]
    assert answers(sim, "2702" + ecu_sim.bench_xor(1, seed).hex()) == ["6702"]
    return sim


# ---- the golden conversation -----------------------------------------------------------
def test_replays_the_flash_conversation(vectors):
    fl = vectors["uds_flash"]
    sim = EcuSim(seed=bytes.fromhex(fl["seed_hex"]), max_block=fl["max_block"], pending=1)
    for step in fl["steps"]:
        assert answers(sim, step["req_hex"]) == step["rsp_hex"], step["name"]
    assert sim.image.hex() == fl["file_hex"]
    assert sim.image_crc() == fl["image_crc32"]
    assert sim.session == 0x01 and not sim.unlocked, "reset at the end"


def test_bench_xor_matches_the_firmware(vectors):
    assert bytes(ecu_sim.BENCH_MASK).hex() == vectors["uds_key"]["mask_hex"]
    for case in vectors["uds_key"]["cases"]:
        assert ecu_sim.bench_xor(case["level"], bytes.fromhex(case["seed_hex"])).hex() == case["key_hex"], case["name"]


# ---- services --------------------------------------------------------------------------
def test_sessions_reset_and_tester_present():
    sim = EcuSim(pending=2)
    assert answers(sim, "1003") == ["5003003201f4"]
    assert answers(sim, "1002") == ["7f1078", "7f1078", "5002003201f4"]
    assert answers(sim, "1002") == ["5002003201f4"], "no pending when already there"
    assert answers(sim, "1004") == ["7f1012"]
    assert answers(sim, "10") == ["7f1013"]
    assert answers(sim, "1101") == ["5101"] and sim.session == 0x01
    assert answers(sim, "3e00") == ["7e00"]
    assert answers(sim, "3e80") == [], "suppressed positive response"
    assert answers(sim, "3e01") == ["7f3e12"]
    assert answers(sim, "2803 01".replace(" ", "")) == ["6803"] and answers(sim, "8502") == ["c502"]
    assert answers(sim, "8582") == []


def test_security_access():
    sim = EcuSim()
    assert answers(sim, "2701") == ["7f277f"], "not in the default session"
    answers(sim, "1003")
    assert answers(sim, "2702" + "00" * 4) == ["7f2724"], "key before seed"
    for expected in ("7f2735", "7f2735", "7f2736"):
        answers(sim, "2701")
        assert answers(sim, "2702" + "00" * 4) == [expected]
    assert answers(sim, "2701") == ["7f2736"], "locked after three wrong keys"
    sim.reset()
    unlocked(sim)
    assert answers(sim, "2701") == ["670100000000"], "zero seed once unlocked"


def test_data_identifiers_and_dtcs():
    sim = EcuSim()
    assert answers(sim, "22f190") == ["62f190" + ecu_sim.VIN.hex()]
    assert answers(sim, "22f1aa") == ["7f2231"]
    assert answers(sim, "2ef15a0102") == ["7f2e33"], "fingerprint needs security"
    unlocked(sim)
    assert answers(sim, "2ef15a0102") == ["6ef15a"]
    assert answers(sim, "22f15a") == ["62f15a0102"]
    assert answers(sim, "2ef1900102") == ["7f2e31"]
    assert answers(sim, "1902ff") == ["5902ff0123452fc0730009"]
    assert answers(sim, "190220") == ["5902ff0123452f"]
    assert answers(sim, "1903ff") == ["7f1912"]
    assert answers(sim, "14ffffff") == ["54"] and answers(sim, "1902ff") == ["5902ff"]
    assert answers(sim, "4400") == ["7f4411"] and answers(sim, "4400", functional=True) == []


def test_download_rules():
    sim = EcuSim(max_block=6)
    assert answers(sim, "3400440000000000000004") == ["7f3433"], "needs security"
    unlocked(sim)
    assert answers(sim, "36010102") == ["7f3624"], "no download"
    assert answers(sim, "37") == ["7f3724"]
    assert answers(sim, "3400500000") == ["7f3431"], "bad ALFID"
    assert answers(sim, "34002200000004") == ["74200006"]
    assert answers(sim, "34002200000004") == ["7f3422"], "one download at a time"
    assert answers(sim, "36020102") == ["7f3673"], "wrong block counter"
    assert answers(sim, "3601010203040506") == ["7f3671"], "longer than the block"
    assert answers(sim, "36010102") == ["7601"]
    assert answers(sim, "37") == ["7f3724"], "short"
    assert answers(sim, "36020304") == ["7602"]
    assert answers(sim, "37") == ["77"]
    assert sim.records == [(0, bytes([1, 2, 3, 4]))]
    assert answers(sim, "3101ff01" + f"{sim.image_crc():08x}") == ["7101ff0100"]
    assert answers(sim, "3101ff0100000000") == ["7101ff0101"], "wrong CRC"
    assert answers(sim, "3101ff02") == ["7f3131"] and answers(sim, "3102ff00") == ["7f3131"]


def test_fault_injection():
    sim = EcuSim(nrc_at=(0x22, 0x22))
    assert answers(sim, "22f190") == ["7f2222"]
    assert answers(sim, "22f190")[0].startswith("62"), "only once"

    sim = unlocked(EcuSim(slow_erase=0.5))
    rsps = sim.handle(bytes.fromhex("3101ff00"))
    assert [(d, r.hex()) for d, r in rsps] == [(0.5, "7f3178"), (0.0, "7101ff0000")]

    sim = unlocked(EcuSim(drop_at_block=2))
    answers(sim, "34002200000004")
    assert answers(sim, "36010102") == ["7601"]
    assert answers(sim, "36020304") == [], "block 2 dropped"


# ---- on a CAN bus ----------------------------------------------------------------------
can = pytest.importorskip("can")
pytest.importorskip("isotp")


@pytest.mark.parametrize("fd", [False, True])
def test_simulator_on_a_virtual_bus(fd):
    import isotp

    channel = f"ecusim-{fd}-{time.perf_counter_ns()}"
    sim = EcuSim()
    stop = threading.Event()
    with can.Bus(interface="virtual", channel=channel, receive_own_messages=False) as ecu_bus, \
            can.Bus(interface="virtual", channel=channel, receive_own_messages=False) as tester_bus:
        notifier, phys, func = ecu_sim.make_stacks(ecu_bus, 0x7E0, 0x7E8, 0x7DF, False, fd, fd)
        server = threading.Thread(target=ecu_sim.serve, args=(sim, phys, func, stop.is_set),
                                  kwargs={"log": lambda *_: None}, daemon=True)
        server.start()
        tnotifier = can.Notifier(tester_bus, [])
        tester = isotp.NotifierBasedCanStack(
            tester_bus, tnotifier, address=isotp.Address(isotp.AddressingMode.Normal_11bits, txid=0x7E0, rxid=0x7E8),
            params=ecu_sim.isotp_params(fd, fd))
        tester.start()
        try:
            tester.send(bytes.fromhex("22f190"))
            rsp = tester.recv(block=True, timeout=3.0)
            assert bytes(rsp) == b"\x62\xf1\x90" + ecu_sim.VIN

            # A response longer than one frame (segmented, flow control)
            sim.dtcs = [(i, 0xFF) for i in range(40)]
            tester.send(bytes.fromhex("1902ff"))
            rsp = tester.recv(block=True, timeout=3.0)
            assert len(rsp) == 3 + 4 * 40
        finally:
            stop.set()
            server.join(2.0)
            for s in (tester, phys, func):
                s.stop()
            tnotifier.stop()
            notifier.stop()
    assert sim.requests[0] == bytes.fromhex("22f190")


def test_command_line_parsers():
    assert ecu_sim.parse_int("0x7E0") == 0x7E0
    assert ecu_sim.parse_nrc_at("36:72") == (0x36, 0x72)
    assert ecu_sim.isotp_params(True, True)["tx_data_length"] == 64
    assert ecu_sim.isotp_params(False, False)["tx_padding"] == 0xCC
