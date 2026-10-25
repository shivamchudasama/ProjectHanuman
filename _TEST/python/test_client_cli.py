# SPDX-License-Identifier: MIT
"""The command line of setu_client.py (main(), find_device, provision,
deprovision, pair, pairstatus, unpair), with a fake `bleak` module: BleakClient is the scripted
SETU server of conftest.py, so caps / ping / send / hex run their real
protocol code. For provision and deprovision, the PC service and the
provisioning session are stand-ins (the protocol itself is
test_provisioning.py; the device side is hil-tests). For pair, bleak's client
reaches the simulated pairing devices of test_pairing.py."""

import asyncio
import os
import struct
import sys
import types
import zlib

import pytest
from cryptography import x509

import setu_client
from blehost.core import gatt_server as gs
from blehost.protocols import provisioning as prov
from conftest import FakeServer

STATUS = prov.DeviceStatus(prov.KEY_READY, 0, 371, bytes(range(32)))


class CliServer(FakeServer):
    """FakeServer that also echoes PING, as the device does."""

    def _on_frame(self, f):
        if f[1] == setu_client.APP_TYPE_PING:
            self._notify(setu_client.frame(setu_client.APP_TYPE_PING, f[2:]))
            return
        super()._on_frame(f)


class FakeBleakClient:
    made = []

    def __init__(self, target, disconnected_callback=None):
        self.target = target
        self.disconnected_callback = disconnected_callback
        self.server = CliServer()
        self.notify_uuid = None
        FakeBleakClient.made.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    @property
    def mtu_size(self):
        return self.server.mtu_size

    async def write_gatt_char(self, uuid, data, response=False):
        await self.server.write_gatt_char(uuid, data, response)

    async def read_gatt_char(self, uuid):
        return await self.server.read_gatt_char(uuid)

    async def start_notify(self, uuid, callback):
        self.notify_uuid = uuid
        self.server.client = types.SimpleNamespace(
            on_notify=callback, data_uuid=setu_client.char_uuid(1, setu_client.PROJECT_BASE),
            caps_uuid=setu_client.char_uuid(3, setu_client.PROJECT_BASE))


@pytest.fixture
def bleak(monkeypatch):
    """A fake bleak: one device called "dev" at AA:BB."""
    found = {"dev": "AA:BB"}

    async def find_device_by_name(name, timeout=10.0):
        return found.get(name)

    mod = types.ModuleType("bleak")
    mod.BleakClient = FakeBleakClient
    mod.BleakScanner = types.SimpleNamespace(find_device_by_name=find_device_by_name)
    monkeypatch.setitem(sys.modules, "bleak", mod)
    FakeBleakClient.made = []
    return mod


def cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["setu_client.py", *argv])
    asyncio.run(setu_client.main())


# ---- find_device ---------------------------------------------------------------------
def test_find_device(bleak, capsys):
    assert asyncio.run(setu_client.find_device("11:22", "anything")) == "11:22"
    assert asyncio.run(setu_client.find_device(None, "dev")) == "AA:BB"
    assert "scanning for 'dev'" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="device 'gone' not found"):
        asyncio.run(setu_client.find_device(None, "gone"))


# ---- transfer commands -----------------------------------------------------------------
def test_caps(bleak, monkeypatch, capsys):
    cli(monkeypatch, "caps", "--name", "dev")
    out = capsys.readouterr().out
    assert "connected, ATT MTU 247 -> 244 B frames, 240 B per DATA frame" in out
    assert "protocol v2, max frame 244 B, window 16" in out
    c = FakeBleakClient.made[0]
    assert c.target == "AA:BB" and c.notify_uuid == setu_client.char_uuid(2, setu_client.PROJECT_BASE)


def test_ping(bleak, monkeypatch, capsys):
    cli(monkeypatch, "ping", "--address", "11:22")
    assert "echo type 0x02 b'ping'" in capsys.readouterr().out


def test_send_reports_the_server_result(bleak, monkeypatch, capsys):
    real_init = CliServer.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.after_end = [(setu_client.APP_TYPE_RESULT, struct.pack("<BII", 0, 1000, 512))]
    monkeypatch.setattr(CliServer, "__init__", init)
    with pytest.raises(SystemExit) as e:
        cli(monkeypatch, "send", "1000", "--name", "dev")
    out = capsys.readouterr().out
    assert e.value.code == 0
    assert "client -> server: 1000 B, OK" in out and "server reports: OK, 1000 B, 512 kbit/s" in out
    app_type, data = FakeBleakClient.made[0].server.objects[0]
    assert app_type == 0x10 and len(data) == 1000


def test_send_failure_exits_non_zero(bleak, monkeypatch, capsys):
    real_init = CliServer.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.reject = 0x04
    monkeypatch.setattr(CliServer, "__init__", init)
    with pytest.raises(SystemExit) as e:
        cli(monkeypatch, "send", "100", "--name", "dev")
    assert e.value.code == 1


def _hex_file(tmp_path):
    """Two segments: 32 bytes at 0x0000 and 16 bytes at 0x1000."""
    def rec(addr, data, rtype=0):
        body = bytes([len(data), addr >> 8, addr & 0xFF, rtype]) + data
        return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()
    lines = [rec(0x0000, bytes(range(16))), rec(0x0010, bytes(range(16, 32))),
             rec(0x1000, bytes(range(100, 116))), ":00000001FF"]
    p = tmp_path / "t.hex"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def test_hex_upload(bleak, monkeypatch, capsys, tmp_path):
    real_init = CliServer.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.after_end = [(setu_client.APP_TYPE_STORED, struct.pack("<BII", 0, 0, 32))]
    monkeypatch.setattr(CliServer, "__init__", init)
    cli(monkeypatch, "hex", _hex_file(tmp_path), "--name", "dev")
    out = capsys.readouterr().out
    assert "t.hex: 2 segment(s), 48 bytes" in out
    assert "0x00000000 32 B: OK" in out and "0x00001000 16 B: OK" in out
    assert "hex upload done" in out
    objs = FakeBleakClient.made[0].server.objects
    assert objs[0] == (setu_client.APP_TYPE_SEGMENT, struct.pack("<I", 0) + bytes(range(32)))
    assert objs[1] == (setu_client.APP_TYPE_SEGMENT, struct.pack("<I", 0x1000) + bytes(range(100, 116)))


def test_hex_upload_stops_at_a_failed_segment(bleak, monkeypatch, tmp_path):
    real_init = CliServer.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.corrupt = True
    monkeypatch.setattr(CliServer, "__init__", init)
    with pytest.raises(SystemExit) as e:
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--name", "dev")
    assert e.value.code == 1 and len(FakeBleakClient.made[0].server.writes) > 0


def test_hex_upload_without_stored_times_out(bleak, monkeypatch, tmp_path):
    async def no_stored(self, addr, data, progress=None):
        raise TimeoutError(f"0x{addr:08x}: no STORED from the server")
    monkeypatch.setattr(setu_client.SETUClient, "upload_segment", no_stored)
    with pytest.raises(SystemExit, match="no STORED"):
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--name", "dev")


@pytest.mark.parametrize("argv, match", [
    (["hex"], "hex: missing .hex file"),
    (["hex", "no_such_file.hex"], "no_such_file.hex"),
])
def test_hex_argument_errors(bleak, monkeypatch, argv, match):
    with pytest.raises(SystemExit, match=match):
        cli(monkeypatch, *argv)
    assert FakeBleakClient.made == [], "nothing connects on a bad argument"


# ---- provision / deprovision --------------------------------------------------------------
class FakePc:
    made = []
    fail = None

    def __init__(self, base, log=print, tap=None, backend_factory=None):
        self.base = base
        self.receiver = "pc-receiver"
        self.started = self.stopped = False
        self.lost = 0
        FakePc.made.append(self)

    async def start(self):
        if FakePc.fail:
            raise gs.GattServerUnavailable(FakePc.fail)
        self.started = True

    async def stop(self):
        self.stopped = True

    def link_lost(self):
        self.lost += 1


class FakeSession:
    made = []
    fail = None

    def __init__(self, client, receiver, log=print, step=None):
        self.client, self.receiver, self.step = client, receiver, step
        self.calls = []
        FakeSession.made.append(self)

    async def provision(self, ca, days):
        self.calls.append(("provision", ca.subject, days))
        self.step("CSR received")
        if FakeSession.fail:
            raise prov.ProvisioningError(FakeSession.fail, 0x05)
        return FakeSession.outcome(ca)

    async def deprovision(self):
        self.calls.append("deprovision")
        if FakeSession.fail:
            raise prov.ProvisioningError(FakeSession.fail)

    async def get_status(self):
        self.calls.append("status")
        return STATUS


@pytest.fixture
def prov_fakes(bleak, monkeypatch):
    FakePc.made, FakePc.fail = [], None
    FakeSession.made, FakeSession.fail = [], None
    FakeSession.outcome = staticmethod(
        lambda ca: prov.Outcome(STATUS, b"csr", ca.certificate, ca.cert_der, "abc1"))
    monkeypatch.setattr(gs, "PcGattServer", FakePc)
    monkeypatch.setattr(prov, "ProvisioningSession", FakeSession)


def test_provision_creates_a_ca_then_reuses_it(prov_fakes, monkeypatch, capsys, tmp_path):
    folder, out = str(tmp_path / "ca"), str(tmp_path / "device.pem")
    cli(monkeypatch, "provision", "--name", "dev", "--ca", folder, "--validity", "90", "--out", out)
    text = capsys.readouterr().out
    assert os.path.exists(os.path.join(folder, "ca_key.pem")), "no CA yet: one is created"
    assert "- CSR received" in text and "provisioned: serial abc1" in text
    assert FakeSession.made[0].calls == [("provision", "CN=BLE Host Provisioning CA", 90)]
    assert FakeSession.made[0].receiver == "pc-receiver"
    pc = FakePc.made[0]
    assert pc.started and pc.stopped and pc.base == setu_client.PROJECT_BASE
    with open(out, "rb") as fh:
        assert x509.load_pem_x509_certificate(fh.read()).subject.rfc4514_string() == \
            "CN=BLE Host Provisioning CA"

    # A link loss reaches the PC service (its running transfer fails)
    FakeBleakClient.made[0].disconnected_callback(None)
    assert pc.lost == 1

    with open(os.path.join(folder, "ca_cert.pem"), "rb") as fh:
        first = fh.read()
    cli(monkeypatch, "provision", "--name", "dev", "--ca", folder)
    with open(os.path.join(folder, "ca_cert.pem"), "rb") as fh:
        assert fh.read() == first, "an existing CA is loaded, not replaced"
    assert FakeSession.made[1].calls[0][2] == 365


def test_provision_with_a_broken_ca_folder(prov_fakes, monkeypatch, tmp_path):
    folder = tmp_path / "ca"
    folder.mkdir()
    (folder / "ca_cert.pem").write_text("not a certificate")
    with pytest.raises(SystemExit, match="CA: no CA in"):
        cli(monkeypatch, "provision", "--name", "dev", "--ca", str(folder))
    assert FakePc.made == []


def test_provision_needs_the_pc_service(prov_fakes, monkeypatch, tmp_path):
    FakePc.fail = "hosting a GATT service needs Windows (WinRT)"
    with pytest.raises(SystemExit, match="PC SETU service not available: hosting"):
        cli(monkeypatch, "provision", "--name", "dev", "--ca", str(tmp_path / "ca"))
    assert FakeBleakClient.made == [], "no connection without the PC service"


def test_provision_failure_stops_the_pc_service(prov_fakes, monkeypatch, tmp_path):
    FakeSession.fail = "device answered BAD_SIG"
    with pytest.raises(SystemExit, match="provisioning failed: device answered BAD_SIG"):
        cli(monkeypatch, "provision", "--name", "dev", "--ca", str(tmp_path / "ca"))
    assert FakePc.made[0].stopped


@pytest.mark.parametrize("failures", [0, 2])
def test_provision_negative(prov_fakes, monkeypatch, capsys, tmp_path, failures):
    seen = []

    async def rejections(session, ca, days):
        seen.append((session, days))
        return failures, FakeSession.outcome(ca)
    monkeypatch.setattr(setu_client, "provision_with_rejections", rejections)
    argv = ["provision", "--negative", "--name", "dev", "--ca", str(tmp_path / "ca")]
    if failures:
        with pytest.raises(SystemExit, match="device verification: 2 case"):
            cli(monkeypatch, *argv)
    else:
        cli(monkeypatch, *argv)
        assert "provisioned: serial abc1" in capsys.readouterr().out
    assert seen[0][0] is FakeSession.made[0] and seen[0][1] == 365
    assert FakeSession.made[0].calls == [], "the negative run replaces the plain one"
    assert FakePc.made[0].stopped


def test_deprovision(prov_fakes, monkeypatch, capsys):
    cli(monkeypatch, "deprovision", "--name", "dev")
    out = capsys.readouterr().out
    assert FakeSession.made[0].calls == ["deprovision", "status"]
    assert FakeSession.made[0].receiver is None, "a wipe needs no PC service"
    assert f"deprovisioned: device KEY_READY, new CSR 371 B, key SHA-256 {bytes(range(8)).hex()}" in out


def test_deprovision_failure(prov_fakes, monkeypatch):
    FakeSession.fail = "refused"
    with pytest.raises(SystemExit, match="deprovisioning failed: refused"):
        cli(monkeypatch, "deprovision", "--name", "dev")


# ---- pair / pairstatus / unpair ---------------------------------------------------------
import functools  # noqa: E402

from blehost.protocols import pairing as pp  # noqa: E402
from test_pairing import A, B, SimDevice  # noqa: E402


class PairBleakClient:
    """BleakClient onto the simulated pairing devices of test_pairing.py."""
    devices = {}

    def __init__(self, target, disconnected_callback=None):
        self.dev = PairBleakClient.devices.get(str(target).upper())
        self.connected = False

    async def connect(self):
        if self.dev is None:
            raise OSError("device not found")
        self.connected = True

    async def disconnect(self):
        self.connected = False
        self.dev.notify_cb = None

    async def read_gatt_char(self, uuid):
        return self.dev.status_bytes()

    async def write_gatt_char(self, uuid, data, response=False):
        await self.dev.control(data)

    async def start_notify(self, uuid, callback):
        self.dev.notify_cb = callback


@pytest.fixture
def pair_bleak(monkeypatch):
    c, p = SimDevice(A[0]), SimDevice(B[0])
    PairBleakClient.devices = {A[0]: c, B[0]: p}
    mod = types.ModuleType("bleak")
    mod.BleakClient = PairBleakClient
    mod.BleakScanner = types.SimpleNamespace()       # addresses are given: never scanned
    monkeypatch.setitem(sys.modules, "bleak", mod)
    monkeypatch.setattr(pp, "PairingOrchestrator", functools.partial(
        pp.PairingOrchestrator, timeout=1.0, fail_grace=0.1, poll=0.02, start_settle=0.0))
    return c, p


def test_pair(pair_bleak, monkeypatch, capsys):
    c, p = pair_bleak
    cli(monkeypatch, "pair", "--central", A[0], "--peripheral", B[0])
    out = capsys.readouterr().out
    assert "START sent" in out and "central: PAIRED as central" in out
    assert "paired: both devices paired" in out
    assert p.controls[0] == pp.encode_start(pp.Role.PERIPHERAL, *A)
    assert c.controls[0] == pp.encode_start(pp.Role.CENTRAL, *B)


def test_pair_failure_exits_non_zero(pair_bleak, monkeypatch, capsys):
    c, p = pair_bleak
    c.outcome, p.outcome = ("fail", pp.Error.OOB_SIG, 0), "lost"
    c.peer_dev, p.peer_dev = p, c
    with pytest.raises(SystemExit) as e:
        cli(monkeypatch, "pair", "--central", A[0], "--peripheral", B[0])
    assert e.value.code == 1
    assert "pairing failed: central: the peer's OOB signature does not verify" in capsys.readouterr().out


def test_pair_not_started_and_arguments(pair_bleak, monkeypatch):
    pair_bleak[1].prov_state = 1
    with pytest.raises(SystemExit, match="pairing not started: the peripheral device is not provisioned"):
        cli(monkeypatch, "pair", "--central", A[0], "--peripheral", B[0])
    with pytest.raises(SystemExit, match="give --central ADDRESS and --peripheral ADDRESS"):
        cli(monkeypatch, "pair", "--central", A[0])
    with pytest.raises(SystemExit, match="give --address"):
        cli(monkeypatch, "pairstatus")


def test_pairstatus_and_unpair(pair_bleak, monkeypatch, capsys):
    c, _ = pair_bleak
    c.state, c.peer, c.peer_type, c.role = pp.State.PAIRED, B[0], 1, 1
    cli(monkeypatch, "pairstatus", "--address", A[0])
    out = capsys.readouterr().out
    assert f"{A[0]}: PAIRED as central, peer {B[0]} (provisioning state 3, own address {A[0]})" in out
    cli(monkeypatch, "unpair", "--address", A[0])
    assert c.controls == [pp.encode_unpair()]
    assert f"{A[0]}: IDLE" in capsys.readouterr().out


# ---- hex --store and fs: the device's file system ------------------------------------------
class FsCliServer(CliServer):
    """CliServer whose device also stores uploads as files and answers file
    commands (FakeFsDevice of conftest.py)."""

    device = None

    def _on_frame(self, f):
        t, p = f[1], f[2:]
        if t == setu_client.APP_TYPE_BEGIN:
            self._notify(setu_client.frame(*FsCliServer.device.begin(p)))
        elif t == setu_client.APP_TYPE_COMMIT:
            self._notify(setu_client.frame(*FsCliServer.device.commit()))
        elif t == 0x40:
            for rt, rp in FsCliServer.device.handle(p):
                self._notify(setu_client.frame(rt, rp))
        else:
            super()._on_frame(f)

    def _end(self):
        n = len(self.objects)
        super()._end()
        if len(self.objects) > n and self.objects[-1][0] == setu_client.APP_TYPE_SEGMENT:
            obj = self.objects[-1][1]
            FsCliServer.device.segment(obj)
            self._notify(setu_client.frame(setu_client.APP_TYPE_STORED, struct.pack("<BII", 0, *struct.unpack("<I", obj[:4]),
                                                                  len(obj) - 4)))


@pytest.fixture
def fsbleak(bleak, monkeypatch, fsdev):
    FsCliServer.device = fsdev
    real_init = FakeBleakClient.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.server = FsCliServer()
    monkeypatch.setattr(FakeBleakClient, "__init__", init)
    return fsdev


def test_hex_store(fsbleak, monkeypatch, capsys, tmp_path):
    cli(monkeypatch, "hex", _hex_file(tmp_path), "--store", "APP1.BIN", "--name", "dev")
    out = capsys.readouterr().out
    image = setu_client.file_image([(0, bytes(range(32))), (0x1000, bytes(range(100, 116)))])
    assert "storing as /FLASH_DISK:/FW/APP1.BIN" in out
    assert f"file /FLASH_DISK:/FW/APP1.BIN: {len(image)} B, crc 0x{zlib.crc32(image):08x} (matches)" in out
    assert fsbleak.files["/FLASH_DISK:/FW/APP1.BIN"] == image


def test_hex_store_refused_or_mismatched(fsbleak, monkeypatch, tmp_path):
    with pytest.raises(SystemExit, match="not a valid file name"):
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--store", "a/b", "--name", "dev")
    fsbleak.busy = True
    with pytest.raises(SystemExit, match="BEGIN APP: BUSY"):
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--store", "APP", "--name", "dev")
    fsbleak.busy = False
    real_commit = fsbleak.commit
    fsbleak.commit = lambda: (0x14, struct.pack("<BBII", 0x13, 9, 0, 0))
    with pytest.raises(SystemExit, match="COMMIT APP: IO"):
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--store", "APP", "--name", "dev")
    fsbleak.commit = lambda: (real_commit(), (0x14, struct.pack("<BBII", 0x13, 0, 7, 7)))[1]
    with pytest.raises(SystemExit, match="device file 7 B crc 0x00000007"):
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--store", "APP", "--name", "dev")


def test_hex_stops_when_stored_reports_an_error(bleak, monkeypatch, tmp_path):
    real_init = CliServer.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.after_end = [(setu_client.APP_TYPE_STORED, struct.pack("<BII", 8, 0, 32))]
    monkeypatch.setattr(CliServer, "__init__", init)
    with pytest.raises(SystemExit) as e:
        cli(monkeypatch, "hex", _hex_file(tmp_path), "--name", "dev")
    assert e.value.code == 1


def test_fs_commands(fsbleak, monkeypatch, capsys, tmp_path):
    cli(monkeypatch, "fs", "mkdir", "FW", "--name", "dev")
    cli(monkeypatch, "fs", "openw", "/FW/a.txt", "--name", "dev")
    cli(monkeypatch, "fs", "write", "hello", "world", "--name", "dev")
    cli(monkeypatch, "fs", "write", "--hex", "0d0a", "--name", "dev")
    cli(monkeypatch, "fs", "close", "--name", "dev")
    cli(monkeypatch, "fs", "ls", "--name", "dev")
    dst = tmp_path / "a.txt"
    cli(monkeypatch, "fs", "get", "/FW/a.txt", str(dst), "--name", "dev")
    out = capsys.readouterr().out
    assert dst.read_bytes() == b"hello world\r\n"
    assert "Directory active: /FLASH_DISK:/FW" in out and "Written, total 13 bytes" in out
    assert "[FILE] /FLASH_DISK:/FW/a.txt (13 bytes)" in out and "File closed, 13 bytes written" in out


def test_fs_errors(fsbleak, monkeypatch):
    with pytest.raises(SystemExit, match="fs: give a command"):
        cli(monkeypatch, "fs", "--name", "dev")
    with pytest.raises(SystemExit, match="unknown command 'format'"):
        cli(monkeypatch, "fs", "format", "--name", "dev")
    with pytest.raises(SystemExit, match="fs cd: CD: NOT_FOUND"):
        cli(monkeypatch, "fs", "cd", "NONE", "--name", "dev")
    with pytest.raises(SystemExit, match="fs mkdir: mkdir requires a path"):
        cli(monkeypatch, "fs", "mkdir", "--name", "dev")
    with pytest.raises(SystemExit, match="fs put"):
        cli(monkeypatch, "fs", "put", "missing.bin", "/x", "--name", "dev")


def test_fs_shell(fsbleak, monkeypatch, capsys):
    lines = iter(["mkdir FW", "openw x", "write abc", "close", "ls"])

    def fake_input(prompt=""):
        try:
            return next(lines)
        except StopIteration:
            raise EOFError from None
    monkeypatch.setattr("builtins.input", fake_input)
    cli(monkeypatch, "fs", "shell", "--name", "dev")
    out = capsys.readouterr().out
    assert "Type 'help'" in out and "[FILE] /FLASH_DISK:/FW/x (3 bytes)" in out


# ---- host authentication -----------------------------------------------------------------
def test_hostcert_issues_a_credential(bleak, monkeypatch, capsys, tmp_path):
    from blehost.pki.authority import CertificateAuthority
    from blehost.pki.host import HostCredential

    ca = CertificateAuthority.create(str(tmp_path / "ca"), {"CN": "CLI CA"})
    host = str(tmp_path / "host")
    cli(monkeypatch, "hostcert", "Bench PC", "--ca", ca.folder, "--host", host, "--validity", "10")
    out = capsys.readouterr().out
    assert "host credential for CN=Bench PC" in out and "keep the folder private" in out
    assert HostCredential.load(host).ca_certificate == ca.certificate
    with pytest.raises(SystemExit, match="already exists"):
        cli(monkeypatch, "hostcert", "Again", "--ca", ca.folder, "--host", host)
    with pytest.raises(SystemExit, match="give the host's name"):
        cli(monkeypatch, "hostcert", "--ca", ca.folder, "--host", str(tmp_path / "h2"))


def test_auth_needs_a_credential(bleak, monkeypatch, tmp_path):
    with pytest.raises(SystemExit, match="issue one with: hostcert NAME"):
        cli(monkeypatch, "auth", "--host", str(tmp_path / "none"))
