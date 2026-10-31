"""A1: plugins with action hooks run inside the ACK transaction; install accepts only reviewed ones."""
import pytest
from alerta.plugins import PluginBase

from voalack.boundary import _check_action_plugins
from voalack.plugin import VoalackCapture
from test_c3_transaction import _Hook


class _ReceiveOnly(PluginBase):
    # PluginBase makes status_change abstract in Alerta 9.1.0, so every plugin implements it
    # and therefore needs review; this one is only a placeholder that is not Voalack's plugin.
    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return None

    def status_change(self, alert, status, text, **kwargs):
        return None


def test_unreviewed_action_plugin_is_refused():
    loaded = {"voalack": VoalackCapture(), "lab-io": _Hook("lab-io")}
    with pytest.raises(RuntimeError, match="lab-io"):
        _check_action_plugins({}, loaded)


def test_reviewed_plugins_are_accepted():
    _check_action_plugins({"VOALACK_REVIEWED_ACTION_PLUGINS": ["lab-io"]},
                          {"voalack": VoalackCapture(), "lab-io": _Hook("lab-io")})


def test_every_other_plugin_needs_review():
    with pytest.raises(RuntimeError, match="status_change"):
        _check_action_plugins({}, {"voalack": VoalackCapture(), "receive": _ReceiveOnly("receive")})


def test_voalack_plugin_is_required():
    with pytest.raises(RuntimeError, match="must be enabled"):
        _check_action_plugins({}, {"receive": _ReceiveOnly("receive")})


def test_instance_assigned_hook_is_inspected():
    # Automated review of bd35994: Alerta calls the hook resolved on the instance.
    replaced = VoalackCapture()
    replaced.post_action = lambda alert, action, text, **kwargs: None
    with pytest.raises(RuntimeError, match="must be enabled"):
        _check_action_plugins({}, {"voalack": replaced})
    with pytest.raises(RuntimeError, match="post_action"):
        _check_action_plugins({}, {"voalack": VoalackCapture(), "extra": replaced})
