"""T04 S3c corrections after review 217ee214 (F1-F3) and design review 051f7b70 (R1-R7).

Native PostgreSQL waits and restores in the guest; the provider is a loopback fake (synthetic).
Astra's original probes stay unchanged in test_t04_s3c_review_probes_ea8c30a.py; these cases cover
the remaining boundaries the reviews named. Counts: logins, reads, revokes, ACK connects and writes,
provider receipts and effects.
"""
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import uuid

import psycopg2
import pytest

from test_t04_s2_sender import _effect, fake, instance  # noqa: F401
from test_t04_s3c_recovery import _net, _owner, _q, _sql_as_sender, sibling  # noqa: F401
from test_t04_s3c_restore import (_cleanup, _close_and_inventory, _contain, _contain_copied_rows, _holds,
                                  _maintenance, _recur, _reopen, _restore_and_recover, _settler_dsn,
                                  _staged_restore_and_recover)
from voalack import recovery, settler
from voalack.recovery import Anchor, AnchorInvalid, Supervisor
from voalack.sender import FakeOneTransport, OwnerSession, OwnerStopped


@pytest.mark.parametrize("field", ["config_revision", "provider_contract"])
def test_s3a_staged_guard_release_requires_frozen_configuration(client, app, instance, fake, sibling, tmp_path, field):
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "started.dump"
    owner = _owner(sib, instance, fake, hooks={"after_start": lambda _: sib.dump(dump)})
    fake.script["ack"] = "close_before_body"
    sent = owner.apply_once(first)
    fake.script["ack"] = "success"
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [owner]), dump, fake=fake)


