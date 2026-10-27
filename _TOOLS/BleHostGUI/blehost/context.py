"""AppContext: the shared objects every panel and feature receives."""

from dataclasses import dataclass

from .core.async_runner import AsyncRunner
from .core.decoders import DecoderRegistry
from .core.devices import DeviceManager
from .core.event_bus import LOG, EventBus
from .core.traffic import TrafficTap

PROJECT_BASE = "16a1-4812-af35-f3f29a92f6ca"         # _ASW/_BLE_GENERIX/BaseUUIDs.h


@dataclass
class Settings:
    base_uuid: str = PROJECT_BASE       # 96-bit base of the SETU service UUIDs
    name_filter: str = "ProjectHanuman"
    scan_timeout: float = 5.0


class AppContext:
    def __init__(self):
        self.settings = Settings()
        self.bus = EventBus()
        self.runner = AsyncRunner()
        self.tap = TrafficTap(self.bus)
        self.decoders = DecoderRegistry()
        self.devices = DeviceManager(self.bus, self.tap)
        self.services = {}              # name -> service of the active device (e.g. "setu"), or the PC's

    @property
    def link(self):
        """The active device's link (core/devices.py); an idle link without one."""
        return self.devices.link

    def log(self, text: str, level: str = "info"):
        """Append to the application log. Any thread."""
        self.bus.post(LOG, (level, text))

    def run(self, coro, on_done=None, on_error=None, on_cancel=None):
        """Run a coroutine on the BLE loop. The callbacks run on the Tk thread:
        on_done(result), on_error(exc) (default: log it), on_cancel()."""
        fut = self.runner.submit(coro)

        def finished(f):
            if f.cancelled():
                if on_cancel:
                    self.bus.call(on_cancel)
                return
            exc = f.exception()
            if exc is not None:
                if on_error:
                    self.bus.call(on_error, exc)
                else:
                    self.log(f"{type(exc).__name__}: {exc}", "error")
            elif on_done:
                self.bus.call(on_done, f.result())

        fut.add_done_callback(finished)
        return fut
