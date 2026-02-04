"""Tests for privilege detection utilities."""

from clawpwn.utils.privileges import (
    can_raw_scan,
    get_privilege_help,
    has_cap_net_raw,
    is_root,
)


def test_is_root_returns_bool():
    """is_root returns a boolean."""
    assert isinstance(is_root(), bool)


def test_has_cap_net_raw_nonexistent_returns_false():
    """has_cap_net_raw returns False for nonexistent binary."""
    assert has_cap_net_raw("nonexistent_binary_xyz_123") is False


def test_can_raw_scan_when_root(monkeypatch):
    """can_raw_scan returns True when running as root."""
    monkeypatch.setattr("clawpwn.utils.privileges.is_root", lambda: True)
    assert can_raw_scan("masscan") is True
    assert can_raw_scan("rustscan") is True


def test_can_raw_scan_when_not_root_no_caps(monkeypatch):
    """can_raw_scan returns False when not root and no caps."""
    monkeypatch.setattr("clawpwn.utils.privileges.is_root", lambda: False)
    monkeypatch.setattr("clawpwn.utils.privileges.has_cap_net_raw", lambda _: False)
    assert can_raw_scan("masscan") is False


def test_get_privilege_help_contains_instructions():
    """get_privilege_help returns a string with setcap and sudo instructions."""
    msg = get_privilege_help("rustscan")
    assert "setcap" in msg
    assert "sudo" in msg
    assert "rustscan" in msg
    assert "cap_net_raw" in msg
