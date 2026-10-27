"""Thread-safe publish/subscribe between the asyncio worker and the Tk thread.

post() and call() may be used from any thread. Subscribers and call()ed
functions always run on the Tk thread, from the pump started by attach().
"""

import queue
from collections import defaultdict

# Topics. Payload types are noted next to each.
LINK_STATE = "link.state"      # (LinkState, dict info) of the active device
DEVICES = "devices"            # (DeviceSession or None, LinkState or None, dict info)
LOG = "log"                    # (level: "info"|"warn"|"error", text)
TRAFFIC = "traffic"            # TrafficEvent

_CALL = object()


class EventBus:
    def __init__(self):
        self._q = queue.SimpleQueue()
        self._subs = defaultdict(list)
        self._root = None
        self._period = 30

    def subscribe(self, topic: str, fn):
        """fn(payload), called on the Tk thread."""
        self._subs[topic].append(fn)

    def post(self, topic: str, payload=None):
        self._q.put((topic, payload))

    def call(self, fn, *args):
        """Run fn(*args) on the Tk thread."""
        self._q.put((_CALL, (fn, args)))

    def attach(self, root, period_ms: int = 30):
        self._root = root
        self._period = period_ms
        root.after(period_ms, self._pump)

    def _pump(self):
        try:
            while True:
                topic, payload = self._q.get_nowait()
                try:
                    if topic is _CALL:
                        fn, args = payload
                        fn(*args)
                    else:
                        for fn in self._subs.get(topic, ()):
                            fn(payload)
                except Exception as e:  # a bad subscriber must not stop the pump
                    import traceback
                    traceback.print_exc()
                    if topic is not LOG:
                        self.post(LOG, ("error", f"internal: {e!r}"))
        except queue.Empty:
            pass
        self._root.after(self._period, self._pump)
