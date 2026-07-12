from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .builtin import BUILTIN_PROFILES


class ProfileManager:
    """Manages scan profiles — loading, creating, listing, deleting."""

    def __init__(self, profiles_dir: Optional[Path] = None):
        if profiles_dir is None:
            self.profiles_dir = Path(__file__).parent.parent.parent / "profiles"
        else:
            self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(exist_ok=True)

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all available profiles (builtin + custom)."""
        profiles = []

        # Built-in profiles
        for name, data in BUILTIN_PROFILES.items():
            profiles.append(
                {
                    "name": name,
                    "description": data["description"],
                    "builtin": True,
                    "path": None,
                }
            )

        # Custom profiles from disk
        for path in self.profiles_dir.glob("*.yaml"):
            name = path.stem
            if name not in BUILTIN_PROFILES:
                try:
                    data = yaml.safe_load(path.read_text(encoding="utf-8"))
                    profiles.append(
                        {
                            "name": data.get("name", name),
                            "description": data.get("description", ""),
                            "builtin": False,
                            "path": str(path),
                        }
                    )
                except Exception:
                    pass

        return profiles

    def load_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Load a profile by name (builtin or custom)."""
        # Check builtin first
        if name in BUILTIN_PROFILES:
            return BUILTIN_PROFILES[name].copy()

        # Check custom profiles
        profile_path = self.profiles_dir / f"{name}.yaml"
        if profile_path.exists():
            try:
                data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
                return data
            except Exception:
                return None

        return None

    def save_profile(self, name: str, data: Dict[str, Any]) -> Path:
        """Save a custom profile to disk."""
        profile_path = self.profiles_dir / f"{name}.yaml"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(
            yaml.dump(data, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        return profile_path

    def delete_profile(self, name: str) -> bool:
        """Delete a custom profile. Returns True if deleted, False if not found or builtin."""
        if name in BUILTIN_PROFILES:
            return False
        profile_path = self.profiles_dir / f"{name}.yaml"
        if profile_path.exists():
            profile_path.unlink()
            return True
        return False

    def apply_to_config(self, config_manager, profile_name: str) -> bool:
        """Apply a profile's settings to a ConfigManager instance."""
        profile = self.load_profile(profile_name)
        if profile is None:
            return False

        # Apply params
        params = profile.get("params", {})
        for key, value in params.items():
            config_manager.set(key, value)

        return True

    def get_profile_modules(self, profile_name: str) -> tuple:
        """Get enabled and disabled modules from a profile. Returns (enabled_list, disabled_list)."""
        profile = self.load_profile(profile_name)
        if profile is None:
            return ([], [])

        modules = profile.get("modules", {})
        enabled = modules.get("enabled", [])
        disabled = modules.get("disabled", [])
        return (enabled, disabled)

    def ensure_builtin_profiles(self):
        """Ensure built-in profile YAML files exist."""
        for name, data in BUILTIN_PROFILES.items():
            path = self.profiles_dir / f"{name}.yaml"
            if not path.exists():
                path.write_text(
                    yaml.dump(data, default_flow_style=False, allow_unicode=True),
                    encoding="utf-8",
                )
