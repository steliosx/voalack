"""An unreviewed override must not inherit Voalack's built-in action-hook exemption."""
import pytest
from voalack.boundary import _check_action_plugins
from voalack.plugin import VoalackCapture


class _UnreviewedCapture(VoalackCapture):
    def post_action(self, alert, action, text, **kwargs):
        # Stands for a custom external-effect hook; no network I/O is run in this probe.
        self.external_effect = (alert.id, action)
        return None


@pytest.mark.parametrize("slot", ["voalack", "extension"])
def test_unreviewed_capture_subclass_action_override_is_refused(slot):
    loaded = {"voalack": VoalackCapture()}
    loaded[slot] = _UnreviewedCapture()
    with pytest.raises(RuntimeError):
        _check_action_plugins({}, loaded)
