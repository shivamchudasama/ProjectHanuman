#!/usr/bin/env python3
"""BLE Host: PC-side GUI for the Project Hanuman firmware.

    pip install -r requirements.txt
    python ble_host_gui.py

See README.md for the layout and how to add a feature.
"""

import tkinter as tk

from blehost.context import AppContext
from blehost.core.gatt_server import PcGattServer
from blehost.features.ecu import EcuFeature
from blehost.features.file_system import FileSystemFeature
from blehost.features.hex_upload import HexUploadFeature
from blehost.features.pairing import PairingFeature
from blehost.features.provisioning import ProvisioningFeature
from blehost.protocols.setu import SETUService
from blehost.ui.main_window import MainWindow

# Feature pages, in rail order. Add new features here.
FEATURES = [HexUploadFeature, FileSystemFeature, EcuFeature, ProvisioningFeature, PairingFeature]


def _dpi_aware():
    """Crisp text on scaled Windows displays (Tk otherwise gets bitmap-stretched)."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass


def main():
    _dpi_aware()
    ctx = AppContext()
    ctx.services[SETUService.NAME] = SETUService(ctx)
    # The PC's own SETU service: the device sends to the PC through it (CSR)
    pc = PcGattServer(ctx.settings.base_uuid, log=lambda t: ctx.log(t, "warn"), tap=ctx.tap)
    ctx.services[PcGattServer.NAME] = pc
    ctx.link.add_disconnect_hook(lambda _link, _reason: pc.link_lost())

    root = tk.Tk()
    root.withdraw()              # shown once built and themed: no white flash, no layout jump
    MainWindow(root, ctx, FEATURES).show()
    ctx.bus.attach(root)
    ctx.runner.start()
    ctx.run(pc.start(), on_done=lambda _: ctx.log("PC SETU service published"),
            on_error=lambda e: ctx.log(f"PC SETU service not available: {e}", "warn"))
    root.mainloop()


if __name__ == "__main__":
    main()
