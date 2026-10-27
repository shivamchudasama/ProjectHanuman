"""The connected boards: one DeviceSession per board, one of them active.

The Device page connects any number of boards. Each gets a BleLink of its own
(primary=False, labelled with the board's name and address tail, so the
traffic monitor tells them apart) and its own link-level services (the SETU
service, made by the session hooks ble_host_gui.py adds). One board is the
active device: ctx.link is its link and the ActiveService proxies in
ctx.services reach its services, so the feature pages act on it without
knowing about the others. The Pairing page uses two connected boards' links.

Events (EventBus):
  DEVICES     (session, state, info) whenever a board's link changes state;
              (None, None, {}) when the active device or the scan changes.
              A session leaves `sessions` when its link is IDLE again.
  LINK_STATE  (state, info) of the active device only. A switch posts IDLE
              {"reason": "switched", "switched": True} for the old one, then
              CONNECTED {..., "switched": True} for the new one.

The active device changes only while no page has work running (is_busy):
set_active() refuses then, and a board that comes up becomes the active
device if there is none or nothing is busy. When the active device's link
goes there is none until the user makes another board active.

Threading: link states arrive on the asyncio loop, set_active() is called on
the Tk thread. `sessions` is replaced, never changed in place, so the Tk side
may iterate it while the loop updates it. Active hooks run on the thread that
changed the active device.
"""

import time

from .ble_link import BleLink, LinkState
from .event_bus import DEVICES, LINK_STATE


def link_label(name: str, address: str) -> str:
    """The traffic monitor's tag for a board's link: 'ProjectHanuman A3:CF'."""
    return f"{name or 'device'} {address[-5:].upper()}"


class DeviceSession:
    """One board: its link and its link-level services (name -> service)."""

    def __init__(self, address: str, name: str, link, manufacturer_data=None):
        self.address = address
        self.name = name
        self.link = link
        self.manufacturer_data = dict(manufacturer_data or {})
        self.services = {}
        self.connected_at = None            # time.monotonic() when the link came up

    @property
    def key(self) -> str:
        return self.address.upper()

    @property
    def state(self) -> LinkState:
        return self.link.state

    @property
    def connected(self) -> bool:
        return self.link.connected

    def has_characteristic(self, uuid: str) -> bool:
        """Whether the connected board's GATT table has uuid."""
        gatt = self.link.gatt
        return bool(self.link.connected and gatt is not None and gatt.has_characteristic(uuid))


class DeviceManager:
    """The boards the GUI is connected to (ctx.devices).

    make_link(label) -> an unconnected link (BleLink by default; tests pass
    fakes). is_busy() -> True while a page has work running (MainWindow sets it).
    """

    def __init__(self, bus, tap, make_link=None, is_busy=None):
        self._bus = bus
        self._make_link = make_link or (lambda label: BleLink(bus, tap, label=label, primary=False))
        self.is_busy = is_busy or (lambda: False)
        self.sessions = {}                  # address (upper case) -> DeviceSession, in connect order
        self.active = None
        self.scanning = False
        self._scanner = self._make_link("scan")
        self.idle_link = self._make_link("")     # ctx.link while there is no active device
        self._session_hooks = []
        self._active_hooks = []

    # ---- hooks -------------------------------------------------------------
    def add_session_hook(self, fn):
        """fn(session) when a session is made, before its link connects: add
        its services and link hooks there."""
        self._session_hooks.append(fn)

    def add_active_hook(self, fn):
        """fn(session or None) when the active device changes."""
        self._active_hooks.append(fn)

    # ---- queries -----------------------------------------------------------
    @property
    def link(self):
        """The active device's link, or an idle one that is never connected."""
        return self.active.link if self.active is not None else self.idle_link

    def get(self, address: str):
        return self.sessions.get((address or "").upper())

    def connected(self) -> list:
        return [s for s in self.sessions.values() if s.connected]

    # ---- scan / connect / disconnect ---------------------------------------
    async def scan(self, timeout: float = 5.0) -> list:
        """Scan (also while boards are connected) -> [ScanResult]."""
        self.scanning = True
        self._changed()
        try:
            return await self._scanner.scan(timeout)
        finally:
            self.scanning = False
            self._changed()

    async def connect(self, address: str, name: str = "", manufacturer_data=None) -> DeviceSession:
        """Connect another board. Raises if it is connected already or the
        connection fails (the session is gone again then)."""
        key = address.upper()
        if key in self.sessions:
            raise RuntimeError(f"{name or address} is connected already")
        session = DeviceSession(address, name, self._make_link(link_label(name, address)),
                                manufacturer_data)
        session.link.on_state = lambda _link, state, info: self._link_state(session, state, info)
        for hook in self._session_hooks:
            hook(session)
        self.sessions = {**self.sessions, key: session}
        self._bus.post(DEVICES, (session, session.state, {}))
        try:
            await session.link.connect(address, name, device=self._scanner.device(address))
        except BaseException:
            self._remove(session)               # also when the link never left IDLE
            raise
        return session

    async def disconnect(self, address: str):
        session = self.get(address)
        if session is not None:
            await session.link.disconnect()

    async def disconnect_all(self):
        for session in list(self.sessions.values()):
            try:
                await session.link.disconnect()
            except Exception:
                pass                            # closing anyway

    # ---- the active device -------------------------------------------------
    def set_active(self, address: str) -> bool:
        """Make a connected board the active device. False if it is not
        connected or a page has work running."""
        session = self.get(address)
        if session is None or not session.connected:
            return False
        if session is self.active:
            return True
        if self.is_busy():
            return False
        self._activate(session, switched=True)
        return True

    def _activate(self, session, switched: bool):
        if self.active is not None:
            self._bus.post(LINK_STATE, (LinkState.IDLE, {"reason": "switched", "switched": True}))
        self.active = session
        info = dict(session.link.info)
        if switched:
            info["switched"] = True
        self._bus.post(LINK_STATE, (LinkState.CONNECTED, info))
        self._run_active_hooks()
        self._changed()

    def _run_active_hooks(self):
        for hook in self._active_hooks:
            hook(self.active)

    # ---- link states (on the loop) -----------------------------------------
    def _link_state(self, session, state, info):
        if state == LinkState.CONNECTED:
            session.connected_at = time.monotonic()
        elif state == LinkState.IDLE:
            self._remove(session)
        self._bus.post(DEVICES, (session, state, dict(info)))
        if session is self.active:
            if state == LinkState.IDLE:
                self.active = None
                self._bus.post(LINK_STATE, (state, dict(info)))
                self._run_active_hooks()
                self._changed()
            else:
                self._bus.post(LINK_STATE, (state, dict(info)))
        elif state == LinkState.CONNECTED and (self.active is None or not self.is_busy()):
            self._activate(session, switched=False)

    def _remove(self, session):
        if self.sessions.get(session.key) is session:
            self.sessions = {k: s for k, s in self.sessions.items() if s is not session}

    def _changed(self):
        self._bus.post(DEVICES, (None, None, {}))

    # ---- this PC's keys, without a link -------------------------------------
    async def is_paired_address(self, address: str) -> bool:
        return await self._scanner.is_paired_address(address)

    async def unpair_address(self, address: str) -> str:
        return await self._scanner.unpair_address(address)


class ActiveService:
    """ctx.services[name]: the active device's service of that name.

    `available` is False without an active device; anything else then raises
    RuntimeError("not connected"), as the service itself does."""

    def __init__(self, devices: DeviceManager, name: str):
        self._devices = devices
        self._name = name

    def target(self):
        session = self._devices.active
        return session.services.get(self._name) if session is not None else None

    @property
    def available(self) -> bool:
        svc = self.target()
        return bool(svc is not None and svc.available)

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)
        svc = self.target()
        if svc is None:
            raise RuntimeError("not connected")
        return getattr(svc, attr)
