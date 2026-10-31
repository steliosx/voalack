"""Test-only server: the Voalack-wrapped Alerta app with a plugin that stalls after set_alert.

Usage: python crash_server.py PORT MARKER. The stall lets the test kill the process while the
ACK and its capture exist only inside the uncommitted request transaction.
"""
import sys
import time
from pathlib import Path

from alerta.plugins import PluginBase

from conftest import CONFIG


class StallAfterSetAlert(PluginBase):
    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return None

    def status_change(self, alert, status, text, **kwargs):
        return None

    def take_action(self, alert, action, text, **kwargs):
        return None

    def post_action(self, alert, action, text, **kwargs):
        Path(sys.argv[2]).write_text("after set_alert, before commit")
        time.sleep(120)


if __name__ == "__main__":
    from alerta.app import plugins
    from voalack.boundary import create_app
    app = create_app(config_override=dict(CONFIG, TESTING=False))
    plugins.plugins["stall"] = StallAfterSetAlert("stall")
    app.run(host="127.0.0.1", port=int(sys.argv[1]), threaded=False, use_reloader=False)
