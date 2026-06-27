import pytest
from pathlib import Path
from wvs.profiles import ProfileManager
from wvs.profiles.builtin import BUILTIN_PROFILES


def test_list_profiles():
    manager = ProfileManager()
    profiles = manager.list_profiles()
    names = [p["name"] for p in profiles]
    assert "default" in names
    assert "src-quick" in names
    assert "pentest-full" in names
    assert "sqli-only" in names


def test_load_builtin_profile():
    manager = ProfileManager()
    profile = manager.load_profile("src-quick")
    assert profile is not None
    assert profile["name"] == "src-quick"
    assert "sqli" in profile["modules"]["enabled"]


def test_load_nonexistent_profile():
    manager = ProfileManager()
    profile = manager.load_profile("nonexistent")
    assert profile is None


def test_save_and_load_custom_profile(tmp_path):
    manager = ProfileManager(profiles_dir=tmp_path)
    data = {
        "name": "test-profile",
        "description": "Test profile",
        "modules": {"enabled": ["sqli"], "disabled": []},
        "params": {"rate": 15, "threads": 5},
    }
    path = manager.save_profile("test-profile", data)
    assert path.exists()

    loaded = manager.load_profile("test-profile")
    assert loaded is not None
    assert loaded["name"] == "test-profile"
    assert loaded["params"]["rate"] == 15


def test_delete_custom_profile(tmp_path):
    manager = ProfileManager(profiles_dir=tmp_path)
    data = {"name": "to-delete", "description": "", "modules": {}, "params": {}}
    manager.save_profile("to-delete", data)

    assert manager.delete_profile("to-delete") is True
    assert manager.load_profile("to-delete") is None


def test_delete_builtin_profile():
    manager = ProfileManager()
    assert manager.delete_profile("default") is False


def test_get_profile_modules():
    manager = ProfileManager()

    enabled, disabled = manager.get_profile_modules("src-quick")
    assert "sqli" in enabled
    assert "xss" in enabled
    assert "xxe" not in enabled

    enabled, disabled = manager.get_profile_modules("sqli-only")
    assert enabled == ["sqli"]


def test_builtin_profiles_all_have_required_fields():
    for name, data in BUILTIN_PROFILES.items():
        assert "name" in data
        assert "description" in data
        assert "modules" in data
        assert "params" in data
        assert "enabled" in data["modules"]
        assert "disabled" in data["modules"]
        assert "rate" in data["params"]
        assert "threads" in data["params"]
        assert "timeout" in data["params"]
        assert "crawl_depth" in data["params"]
        assert "crawl_max_urls" in data["params"]
        assert "verify_ssl" in data["params"]
