"""Audit 2026-11-08 finding 7: a short write never replaces the recovery anchor.

The supervisor rewrote the anchor log through one os.write call and ignored a short count, so a
full disk could swap a cut-off copy in for the good file. Now every byte is written (looping over
short writes), the length is checked after fsync, and only then is the file replaced; a write
that cannot progress raises before the good file is touched, and no temporary file is left.
Pure filesystem tests: no database is used.
"""
import errno
import os
import subprocess
import tempfile

import pytest

from voalack.recovery import LOG, Anchor, Supervisor

REAL_WRITE = os.write


def _under(directory, fd):
    try:
        return os.readlink(f"/proc/self/fd/{fd}").startswith(directory + os.sep)
    except OSError:
        return False


def _genesis(directory):
    head = Supervisor(directory).append(None, "open", bootstrap=True)
    return head, open(os.path.join(directory, LOG), "rb").read()


def _leftovers(directory):
    return sorted(n for n in os.listdir(directory) if n.endswith(".tmp"))


def test_short_writes_are_completed(tmp_path, monkeypatch):
    d = str(tmp_path)
    genesis, _ = _genesis(d)
    calls = []

    def capped(fd, data):
        if not _under(d, fd):
            return REAL_WRITE(fd, data)
        calls.append(len(data))
        return REAL_WRITE(fd, bytes(data[:7]))        # at most 7 bytes per call
    monkeypatch.setattr(os, "write", capped)
    head = Supervisor(d).append((genesis.seq, genesis.sha256), "closed")
    monkeypatch.undo()
    assert len(calls) > 1                                # the loop really saw short writes
    assert Anchor(d).head() == head and head.phase == "closed" and head.seq == 2
    assert _leftovers(d) == []


@pytest.mark.parametrize("second", ["enospc", "zero"])
def test_a_write_that_cannot_finish_leaves_the_anchor_untouched(tmp_path, monkeypatch, second):
    d = str(tmp_path)
    genesis, before = _genesis(d)
    calls = []

    def full_disk(fd, data):
        if not _under(d, fd):
            return REAL_WRITE(fd, data)
        calls.append(len(data))
        if len(calls) == 1:
            return REAL_WRITE(fd, bytes(data[:len(data) // 2]))   # the first call writes half
        if second == "zero":
            return 0
        raise OSError(errno.ENOSPC, "lab: no space left on device")
    monkeypatch.setattr(os, "write", full_disk)
    with pytest.raises(OSError) as exc:
        Supervisor(d).append((genesis.seq, genesis.sha256), "closed")
    monkeypatch.undo()
    assert exc.value.errno == errno.ENOSPC
    assert open(os.path.join(d, LOG), "rb").read() == before
    assert Anchor(d).head() == genesis and _leftovers(d) == []
    head = Supervisor(d).append((genesis.seq, genesis.sha256), "closed")     # space again: the write succeeds
    assert Anchor(d).head() == head and head.seq == 2


def test_a_real_full_filesystem_leaves_the_anchor_untouched():
    """[lab, root guest only] A tiny tmpfs fills up during the rewrite of the anchor log."""
    if os.geteuid() != 0:
        pytest.skip("needs root to mount a tmpfs")
    mount = tempfile.mkdtemp(prefix="voalack-anchor-full-")
    if subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64k", "tmpfs", mount]).returncode != 0:
        os.rmdir(mount)
        pytest.skip("tmpfs mount failed")
    try:
        d = os.path.join(mount, "anchor")
        genesis, before = _genesis(d)
        filler = os.open(os.path.join(mount, "filler"), os.O_WRONLY | os.O_CREAT, 0o600)
        try:                                                          # fill the filesystem completely
            while REAL_WRITE(filler, b"\0" * 1024) > 0:
                pass
        except OSError as exc:
            assert exc.errno == errno.ENOSPC
        finally:
            os.close(filler)
        with pytest.raises(OSError):
            Supervisor(d).append((genesis.seq, genesis.sha256), "closed")
        assert open(os.path.join(d, LOG), "rb").read() == before
        assert Anchor(d).head() == genesis and _leftovers(d) == []
    finally:
        subprocess.run(["umount", mount])
        os.rmdir(mount)
