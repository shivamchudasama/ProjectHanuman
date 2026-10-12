"""SETU protocol glue: reuse of the reference client, traffic decoding and the
per-connection SETU service.

The protocol itself lives in setu_client.py next to ble_host_gui.py and is
not duplicated here.
"""

import os
import struct
import sys

_GUI_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _GUI_DIR not in sys.path:
    sys.path.insert(0, _GUI_DIR)

import setu_client  # noqa: E402  (path set up above)

from ..core.decoders import DecoderRegistry  # noqa: E402

DATA_ID, CTRL_ID, CAPS_ID = 1, 2, 3
APP_TYPE_MAX = 0xEF                                  # SETU_APP_TYPE_MAX
_FRAME_NAMES = {setu_client.T_START: "START", setu_client.T_DATA: "DATA", setu_client.T_ACK: "ACK", setu_client.T_NACK: "NACK",
                setu_client.T_END: "END", setu_client.T_ABORT: "ABORT"}

# appType registry: app_type -> (name, short-message decoder or None).
# Application features register the types they use (see register_app_type).
_APP_TYPES = {setu_client.APP_TYPE_RESULT: ("RESULT", None), setu_client.APP_TYPE_PING: ("PING", None)}


def register_app_type(app_type: int, name: str, short_decoder=None):
    """Name an appType for the traffic monitor. short_decoder(payload) -> str
    formats it when it is sent as a short message."""
    _APP_TYPES[app_type] = (name, short_decoder)


def _status(v: int) -> str:
    return setu_client.STATUS.get(v, f"0x{v:02x}")


def _app_name(t: int) -> str:
    return _APP_TYPES.get(t, (f"app 0x{t:02x}", None))[0]


def decode_frame(data: bytes) -> tuple:
    """One SETU frame -> (kind, summary)."""
    if len(data) < 2:
        return "?", "short frame"
    ln, ft, p = data[0], data[1], data[2:]
    bad = "" if ln == len(p) else f" (len field {ln}, got {len(p)})"
    if ft <= APP_TYPE_MAX:
        name, fn = _APP_TYPES.get(ft, (f"app 0x{ft:02x}", None))
        return "SHORT", f"{name} {fn(p) if fn else p.hex(' ')}{bad}"
    kind = _FRAME_NAMES.get(ft, f"0x{ft:02x}")
    if ft == setu_client.T_START and len(p) >= 12:
        xid, app, total, chunk, win, crc = struct.unpack("<BBIBBI", p[:12])
        s = f"xid={xid} {_app_name(app)} len={total} chunk={chunk} win={win} crc=0x{crc:08x}"
    elif ft == setu_client.T_DATA and len(p) >= 2:
        s = f"xid={p[0]} seq={p[1]} {len(p) - 2} B"
    elif ft == setu_client.T_ACK and len(p) >= 3:
        s = f"xid={p[0]} next={p[1]} win={p[2]}"
    elif ft == setu_client.T_NACK and len(p) >= 3:
        s = f"xid={p[0]} next={p[1]} reason={_status(p[2])}"
    elif ft == setu_client.T_END and len(p) >= 2:
        s = f"xid={p[0]} {_status(p[1])}"
    elif ft == setu_client.T_ABORT and len(p) >= 3:
        s = f"xid={p[0]} {_status(p[1])} by {'sender' if p[2] == setu_client.ABORT_BY_SENDER else 'receiver'}"
    else:
        s = p.hex(" ")
    return kind, f"{kind} {s}{bad}"


def decode_caps(data: bytes) -> tuple:
    if len(data) < 3:
        return "", data.hex(" ")
    return "CAPS", f"CAPS v{data[0]} max frame {data[1]} window {data[2]}"


def register_decoders(reg: DecoderRegistry, base: str):
    reg.register(setu_client.char_uuid(DATA_ID, base), "DATA", decode_frame)
    reg.register(setu_client.char_uuid(CTRL_ID, base), "CTRL", decode_frame)
    reg.register(setu_client.char_uuid(CAPS_ID, base), "CAPS", decode_caps)


class SETUService:
    """SETU client endpoint of the current connection, shared by features.

    On connect it subscribes to CTRL. A feature that wants to transfer calls
    new_client() — the frame size is taken from the ATT MTU at that moment —
    and notifications are routed to that client. A feature that follows the
    device for a long time (a UDS flash job) takes routed_client(first, last)
    instead: short messages of that appType range go to it, whichever client
    another page has taken since. Routes end with the link.
    """

    NAME = "setu"

    def __init__(self, ctx):
        self.ctx = ctx
        self.available = False
        self.client = None
        self.routes = []                 # (first appType, last appType, client)
        self.base = ctx.settings.base_uuid
        register_decoders(ctx.decoders, self.base)
        ctx.link.add_connect_hook(self._attach)
        ctx.link.add_disconnect_hook(self._detach)

    async def _attach(self, link):
        self.base = self.ctx.settings.base_uuid
        register_decoders(self.ctx.decoders, self.base)
        ctrl = setu_client.char_uuid(CTRL_ID, self.base)
        if not link.gatt.has_characteristic(ctrl):
            self.ctx.log(f"no SETU service with base {self.base} on this device", "warn")
            return
        await link.start_notify(ctrl, self._on_ctrl)
        self.available = True
        self.ctx.log("SETU service found, subscribed to CTRL")

    def _detach(self, _link, _reason):
        self.available = False
        self.client = None
        self.routes = []

    def _on_ctrl(self, handle, data):
        if len(data) >= 2 and data[1] <= APP_TYPE_MAX:
            for first, last, cli in self.routes:
                if first <= data[1] <= last:
                    cli.on_notify(handle, data)
                    return
        if self.client is not None:
            self.client.on_notify(handle, data)

    def _require(self):
        if self.ctx.link.gatt is None:
            raise RuntimeError("not connected")
        if not self.available:
            raise RuntimeError("the device has no SETU service")

    def new_client(self) -> "setu_client.SETUClient":
        """Must be called on the BLE loop."""
        self._require()
        self.client = setu_client.SETUClient(self.ctx.link.gatt, self.base,
                                        log=lambda t: self.ctx.log(t, "warn"))
        return self.client

    def routed_client(self, first: int, last: int) -> "setu_client.SETUClient":
        """A client that receives the short messages of appTypes first..last,
        replacing an earlier route of the same range. Must be called on the BLE loop."""
        self._require()
        cli = setu_client.SETUClient(self.ctx.link.gatt, self.base, log=lambda t: self.ctx.log(t, "warn"))
        self.routes = [r for r in self.routes if (r[0], r[1]) != (first, last)] + [(first, last, cli)]
        return cli

    async def read_caps(self) -> tuple:
        """-> (protocol version, max frame, window, ATT MTU)"""
        self._require()
        probe = setu_client.SETUClient(self.ctx.link.gatt, self.base)
        return (*await probe.read_caps(), self.ctx.link.mtu_size)
