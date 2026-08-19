"""Settings validation and the console's settings routes.

The point of these tests is that a rejected form leaves the stored config
untouched. A settings page that half-saves is worse than one that does not
exist, because the operator believes the workspace is in a state it is not.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.settings import (
    LOCKED_FACTS,
    SettingsError,
    apply_executor,
    apply_instance_add,
    apply_instance_update,
    apply_notifications,
    apply_policy,
    apply_scanning,
    apply_ui,
    defaults,
    merged,
)


def test_merged_fills_defaults_without_mutating_the_stored_config():
    stored = {"instances": [{"url": "https://x.service-now.com"}]}
    out = merged(stored)
    assert out["global_dry_run"] is True
    assert out["executor"]["kind"] == "none"
    assert stored == {"instances": [{"url": "https://x.service-now.com"}]}


def test_instance_requires_https():
    cfg = defaults()
    with pytest.raises(SettingsError) as exc:
        apply_instance_add(cfg, {"url": "http://dev1.service-now.com", "user": "admin"})
    assert "https" in str(exc.value)
    assert cfg["instances"] == []


def test_instance_add_and_duplicate_refused():
    cfg = defaults()
    msg = apply_instance_add(cfg, {"url": "https://dev1.service-now.com/", "user": "admin",
                                   "environment": "test"})
    assert "dev1" in msg
    inst = cfg["instances"][0]
    assert inst["url"] == "https://dev1.service-now.com"  # trailing slash normalised
    assert inst["environment"] == "test"
    with pytest.raises(SettingsError):
        apply_instance_add(cfg, {"url": "https://dev1.service-now.com", "user": "admin"})


def test_instance_update_keeps_password_when_blank():
    cfg = defaults()
    apply_instance_add(cfg, {"url": "https://d.service-now.com", "user": "admin", "password": "s3cret"})
    apply_instance_update(cfg, {"index": "0", "name": "dev", "environment": "prod", "user": "svc"})
    assert cfg["instances"][0]["password"] == "s3cret"
    assert cfg["instances"][0]["environment"] == "prod"


def test_instance_delete_also_drops_its_autonomy_ceiling():
    cfg = defaults()
    apply_instance_add(cfg, {"url": "https://d.service-now.com", "user": "a", "name": "dev"})
    cfg["autonomy_ceilings"]["dev"] = "A2"
    apply_instance_update(cfg, {"index": "0", "delete": "on"})
    assert cfg["instances"] == []
    assert "dev" not in cfg["autonomy_ceilings"]


def test_policy_records_only_actual_changes():
    cfg = defaults()
    cfg["autonomy_ceilings"] = {"dev": "A1"}
    _msg, decisions = apply_policy(cfg, {"form": "policy", "ceiling:dev": "A1", "global_dry_run": "on"})
    assert decisions == [], "an unchanged value is not a decision worth recording"
    _msg, decisions = apply_policy(cfg, {"form": "policy", "ceiling:dev": "A2"})
    assert any("autonomy_ceiling[dev] A1 -> A2" in d for d in decisions)
    assert any("global_dry_run True -> False" in d for d in decisions)


def test_a_post_without_the_form_marker_cannot_disable_dry_run():
    """An unchecked checkbox submits nothing. Absence must not mean 'off' for
    the one setting whose default is the safety posture."""
    cfg = defaults()
    assert cfg["global_dry_run"] is True
    apply_policy(cfg, {"ceiling:dev": "A2"})  # no form marker: a partial or crafted POST
    assert cfg["global_dry_run"] is True


def test_policy_rejects_an_invented_autonomy_class():
    cfg = defaults()
    with pytest.raises(SettingsError):
        apply_policy(cfg, {"ceiling:dev": "A4"})


def test_executor_needs_somewhere_to_send_the_fix():
    cfg = defaults()
    cfg["executor"]["command"] = ""
    with pytest.raises(SettingsError):
        apply_executor(cfg, {"kind": "nowaikit", "url": "", "command": ""})


def test_executor_refuses_cleartext_url():
    cfg = defaults()
    with pytest.raises(SettingsError):
        apply_executor(cfg, {"kind": "nowaikit", "url": "http://box:8931/mcp"})


def test_executor_change_is_a_recorded_decision():
    cfg = defaults()
    _msg, decisions = apply_executor(
        cfg, {"kind": "nowaikit", "command": "npx -y nowaikit-mcp", "update_set_prefix": "ROB"})
    assert decisions == ["executor none -> nowaikit"]


def test_notifications_reject_a_non_address():
    cfg = defaults()
    with pytest.raises(SettingsError):
        apply_notifications(cfg, {"to": "platform.owner"})


def test_notifications_split_recipients_and_keep_password_when_blank():
    cfg = defaults()
    cfg["email"]["password"] = "kept"
    msg = apply_notifications(cfg, {"to": "a@x.com, b@x.com; c@x.com", "port": "587", "starttls": "on"})
    assert cfg["email"]["to"] == ["a@x.com", "b@x.com", "c@x.com"]
    assert cfg["email"]["port"] == 587 and cfg["email"]["starttls"] is True
    assert cfg["email"]["password"] == "kept"
    assert "3 recipient" in msg


def test_notifications_say_so_when_nothing_is_configured():
    cfg = defaults()
    assert "stay silent" in apply_notifications(cfg, {"to": "", "webhook_url": ""})


def test_port_must_be_a_number_in_range():
    cfg = defaults()
    with pytest.raises(SettingsError):
        apply_notifications(cfg, {"to": "a@x.com", "port": "not-a-port"})
    with pytest.raises(SettingsError):
        apply_notifications(cfg, {"to": "a@x.com", "port": "99999"})


def test_scanning_and_ui_round_trip():
    cfg = defaults()
    apply_scanning(cfg, {"include_shadow": "on"})
    assert cfg["scanning"] == {"include_shadow": True, "upgrade_planned": False}
    apply_ui(cfg, {"role": "security", "redact_identifiers": "on"})
    assert cfg["ui"]["role"] == "security" and cfg["ui"]["redact_identifiers"] is True
    assert cfg["ui"]["show_sla_dates"] is False
    with pytest.raises(SettingsError):
        apply_ui(cfg, {"role": "ceo"})


def test_locked_facts_name_the_controls_that_are_not_settings():
    joined = " ".join(title + why for title, why in LOCKED_FACTS)
    for expected in ("sys_security_acl", "background", "sub-production", "baseline"):
        assert expected in joined.lower(), expected
