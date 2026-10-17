# SPDX-License-Identifier: MIT
"""The device's flash conversation (wire.json "uds_flash", checked byte for byte
by the C test uds_job and by test_ecu_sim.py) against python-udsoncan, an ISO
14229 implementation written by someone else. Both sides of the other tests come
from this repo; this one does not: every request must be what udsoncan encodes
for the same service and parameters, every answer one it accepts."""

import json
import pathlib

import pytest

udsoncan = pytest.importorskip("udsoncan")
from udsoncan import CommunicationType, MemoryLocation, Request, Response  # noqa: E402
from udsoncan import services as S  # noqa: E402

WIRE = pathlib.Path(__file__).resolve().parents[1] / "vectors" / "wire.json"
STEPS = {s["name"]: s for s in json.loads(WIRE.read_text())["uds_flash"]["steps"]}


def req(name: str) -> bytes:
    return bytes.fromhex(STEPS[name]["req_hex"])


def _download(name: str) -> bytes:
    d = req(name)
    loc = MemoryLocation(int.from_bytes(d[3:7], "big"), int.from_bytes(d[7:11], "big"),
                         address_format=32, memorysize_format=32)
    return S.RequestDownload.make_request(memory_location=loc).get_payload()


def _routine(name: str, rid: int) -> bytes:
    return S.RoutineControl.make_request(rid, S.RoutineControl.ControlType.startRoutine,
                                         data=req(name)[4:]).get_payload()


EXPECTED = {
    "ext_session": lambda: S.DiagnosticSessionControl.make_request(3).get_payload(),
    "dtc_off": lambda: S.ControlDTCSetting.make_request(2).get_payload(),
    "comm_off": lambda: S.CommunicationControl.make_request(
        3, CommunicationType(subnet=0, normal_msg=True)).get_payload(),
    "prog_session": lambda: S.DiagnosticSessionControl.make_request(2).get_payload(),
    "seed": lambda: S.SecurityAccess.make_request(1, S.SecurityAccess.Mode.RequestSeed).get_payload(),
    "key": lambda: S.SecurityAccess.make_request(1, S.SecurityAccess.Mode.SendKey, data=req("key")[2:]).get_payload(),
    "erase_0": lambda: _routine("erase_0", 0xFF00),
    "erase_1": lambda: _routine("erase_1", 0xFF00),
    "download_0": lambda: _download("download_0"),
    "download_1": lambda: _download("download_1"),
    "exit_0": lambda: S.RequestTransferExit.make_request().get_payload(),
    "exit_1": lambda: S.RequestTransferExit.make_request().get_payload(),
    "check": lambda: _routine("check", 0xFF01),
    "reset": lambda: S.ECUReset.make_request(1).get_payload(),
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_request_is_what_udsoncan_encodes(name):
    assert req(name) == EXPECTED[name]()


@pytest.mark.parametrize("name", sorted(n for n in STEPS if n.startswith("transfer_")))
def test_transfer_data_is_what_udsoncan_encodes(name):
    t = req(name)
    assert t == S.TransferData.make_request(t[1], t[2:]).get_payload()


def test_fingerprint_is_a_write_data_by_identifier():
    # udsoncan needs a codec per DID; the frame is checked by its layout instead
    w = Request.from_payload(req("fingerprint"))
    assert w.service is S.WriteDataByIdentifier and req("fingerprint")[1:3] == b"\xf1\x5a"


@pytest.mark.parametrize("name", sorted(STEPS))
def test_every_answer_is_valid_for_its_request(name):
    request = Request.from_payload(req(name))
    for rsp_hex in STEPS[name].get("rsp_hex", []):
        rsp = Response.from_payload(bytes.fromhex(rsp_hex))
        assert rsp.valid, rsp_hex
        if rsp.positive:
            assert rsp.service is request.service, rsp_hex
        else:
            assert rsp.code == Response.Code.RequestCorrectlyReceived_ResponsePending, rsp_hex


def test_max_block_length_as_udsoncan_reads_it():
    rsp = Response.from_payload(bytes.fromhex(STEPS["download_0"]["rsp_hex"][0]))
    S.RequestDownload.interpret_response(rsp)
    assert rsp.service_data.max_length == json.loads(WIRE.read_text())["uds_flash"]["max_block"]
