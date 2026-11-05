"""JARO WPF - Cost Manager & Data Consumption Budget Enforcer (Phase 3).

Key Guarantees:
- Supports three explicit cost profiles: FREE, METERED, and UNKNOWN.
- Never assumes an Ethernet or Wi-Fi interface is FREE unless explicitly configured
  by the user (prevents accidental consumption on USB/Wi-Fi mobile tethering).
- Blocks probes and bandwidth tests on METERED interfaces unless authorized.
- Enforces configurable per-test and per-session byte consumption limits.
"""
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_PROFILES_PATH = Path(__file__).resolve().parents[2] / "configs" / "network_profiles.json"

CELLULAR_PREFIXES = ("wwan", "rmnet", "ppp", "pdp_ip", "ccmni")


class CostProfile(str, Enum):
    """Explicit data cost classification for a network interface."""
    FREE = "free"
    UNKNOWN = "unknown"
    METERED = "metered"


COST_PRIORITY_POINTS: Dict[CostProfile, float] = {
    CostProfile.FREE: 25.0,
    CostProfile.UNKNOWN: 15.0,
    CostProfile.METERED: 5.0,
}

COST_TIER_BY_PROFILE: Dict[CostProfile, int] = {
    CostProfile.FREE: 0,
    CostProfile.UNKNOWN: 1,
    CostProfile.METERED: 2,
}


def profile_to_cost_tier(profile: CostProfile | str) -> int:
    """Maps a CostProfile (FREE, UNKNOWN, METERED) to a numeric cost tier (0, 1, 2)."""
    resolved = profile if isinstance(profile, CostProfile) else CostProfile(str(profile).lower())
    return COST_TIER_BY_PROFILE[resolved]


class CostManager:
    """Evaluates interface cost profiles, authorization gates, and byte consumption budgets."""

    def __init__(
        self,
        profiles_path: Path = DEFAULT_PROFILES_PATH,
        allow_metered: Optional[bool] = None,
        allow_unknown: Optional[bool] = None,
        allow_external_lab_unknown: Optional[bool] = None,
        max_session_bytes: Optional[int] = None,
        max_single_test_bytes: Optional[int] = None,
    ) -> None:
        self.profiles_path = profiles_path
        raw_cfg = self._load_config()
        policies = raw_cfg.get("default_policies", {})

        self.allow_metered: bool = (
            bool(policies.get("allow_metered_probes", False))
            if allow_metered is None
            else allow_metered
        )
        self.allow_unknown: bool = (
            bool(policies.get("allow_unknown_cost_probes", True))
            if allow_unknown is None
            else allow_unknown
        )
        self.allow_external_lab_unknown: bool = (
            bool(policies.get("allow_external_lab_on_unknown_cost", False))
            if allow_external_lab_unknown is None
            else allow_external_lab_unknown
        )
        self.assume_ethernet_is_free: bool = bool(policies.get("assume_ethernet_is_free", False))
        self.max_session_bytes: int = (
            int(policies.get("max_session_probe_bytes", 262144))
            if max_session_bytes is None
            else max_session_bytes
        )
        self.max_single_test_bytes: int = (
            int(policies.get("max_single_bandwidth_test_bytes", 65536))
            if max_single_test_bytes is None
            else max_single_test_bytes
        )

        self._manual_profiles: Dict[str, CostProfile] = {}
        for ifname, prof_str in raw_cfg.get("manual_interface_profiles", {}).items():
            try:
                self._manual_profiles[ifname] = CostProfile(prof_str.lower())
            except ValueError:
                continue

        self.bytes_consumed_total: int = 0
        self.bytes_by_interface: Dict[str, int] = {}

    def _load_config(self) -> Dict[str, Any]:
        if not self.profiles_path.is_file():
            return {}
        with open(self.profiles_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def set_interface_profile(
        self,
        ifname: str,
        profile: CostProfile | str,
        persist: bool = False,
    ) -> CostProfile:
        """Manually configures whether an interface is FREE, METERED, or UNKNOWN."""
        resolved = profile if isinstance(profile, CostProfile) else CostProfile(profile.lower())
        self._manual_profiles[ifname] = resolved

        if persist and self.profiles_path.is_file():
            cfg = self._load_config()
            manual = cfg.setdefault("manual_interface_profiles", {})
            manual[ifname] = resolved.value
            with open(self.profiles_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)

        return resolved

    def clear_interface_profile(self, ifname: str) -> None:
        """Removes a manual override, reverting the interface to automatic classification."""
        self._manual_profiles.pop(ifname, None)

    def classify_interface(
        self,
        ifname: str,
        medium: str = "unknown",
        os_metered_hint: Optional[bool] = None,
    ) -> CostProfile:
        """Determines the CostProfile of an interface without assuming Ethernet or Wi-Fi is free."""
        if ifname in self._manual_profiles:
            return self._manual_profiles[ifname]

        lower = ifname.lower()
        if lower == "lo":
            return CostProfile.FREE

        if lower.startswith(CELLULAR_PREFIXES) or medium == "cellular":
            return CostProfile.METERED

        if os_metered_hint is True:
            return CostProfile.METERED

        if medium == "ethernet" and self.assume_ethernet_is_free:
            return CostProfile.FREE

        # Never blindly assume Ethernet or Wi-Fi is free (could be USB/Wi-Fi hotspot tethering)
        return CostProfile.UNKNOWN

    def cost_tier_for_interface(
        self,
        ifname: str,
        medium: str = "unknown",
        os_metered_hint: Optional[bool] = None,
    ) -> int:
        """Returns numeric cost tier (0=free, 1=unknown, 2=metered) for an interface via CostManager."""
        prof = self.classify_interface(ifname=ifname, medium=medium, os_metered_hint=os_metered_hint)
        return COST_TIER_BY_PROFILE[prof]

    def _resolve_profiles(self, active_interfaces: List[Dict[str, Any]]) -> List[CostProfile]:
        profiles: List[CostProfile] = []
        for iface in active_interfaces:
            prof_val = iface.get("cost_profile")
            if isinstance(prof_val, CostProfile):
                profiles.append(prof_val)
            elif isinstance(prof_val, str):
                try:
                    profiles.append(CostProfile(prof_val))
                except ValueError:
                    profiles.append(
                        self.classify_interface(
                            iface.get("name", ""),
                            medium=iface.get("medium", "unknown"),
                            os_metered_hint=iface.get("os_metered_hint"),
                        )
                    )
            else:
                profiles.append(
                    self.classify_interface(
                        iface.get("name", ""),
                        medium=iface.get("medium", "unknown"),
                        os_metered_hint=iface.get("os_metered_hint"),
                    )
                )
        return profiles

    def evaluate_network_gate(self, active_interfaces: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Checks whether probing/testing is permitted across the currently active interfaces."""
        if not active_interfaces:
            return {
                "allowed": False,
                "effective_profile": CostProfile.UNKNOWN.value,
                "cost_tier": COST_TIER_BY_PROFILE[CostProfile.UNKNOWN],
                "reason": "No active non-loopback network interfaces available",
            }

        profiles = self._resolve_profiles(active_interfaces)

        # A probe is not bound to one interface. Use the most restrictive active
        # profile so a concurrent metered path cannot bypass the user's guard.
        if CostProfile.METERED in profiles:
            effective = CostProfile.METERED
        elif CostProfile.UNKNOWN in profiles:
            effective = CostProfile.UNKNOWN
        else:
            effective = CostProfile.FREE

        if effective == CostProfile.METERED and not self.allow_metered:
            return {
                "allowed": False,
                "effective_profile": effective.value,
                "cost_tier": COST_TIER_BY_PROFILE[effective],
                "reason": "Blocked by CostManager: active connection is METERED and user has not authorized metered data usage",
            }

        if effective == CostProfile.UNKNOWN and not self.allow_unknown:
            return {
                "allowed": False,
                "effective_profile": effective.value,
                "cost_tier": COST_TIER_BY_PROFILE[effective],
                "reason": "Blocked by CostManager: active connection has UNKNOWN cost profile and unknown-cost probes are disabled",
            }

        return {
            "allowed": True,
            "effective_profile": effective.value,
            "cost_tier": COST_TIER_BY_PROFILE[effective],
            "priority_points": COST_PRIORITY_POINTS[effective],
            "reason": None,
        }

    # Backward-compatible alias for Phase 3 callers
    evaluate_network_Gate = evaluate_network_gate

    def evaluate_external_lab_gate(
        self,
        active_interfaces: List[Dict[str, Any]],
        authorize_unknown: Optional[bool] = None,
        authorize_metered: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Strict authorization gate for external NetworkLab suites.

        Requires explicit authorization whenever the effective cost profile is UNKNOWN or METERED.
        """
        if not active_interfaces:
            return {
                "allowed": False,
                "requires_authorization": False,
                "effective_profile": CostProfile.UNKNOWN.value,
                "cost_tier": COST_TIER_BY_PROFILE[CostProfile.UNKNOWN],
                "reason": "No active non-loopback network interfaces available",
            }

        profiles = self._resolve_profiles(active_interfaces)
        if CostProfile.FREE in profiles and CostProfile.METERED not in profiles:
            effective = CostProfile.FREE
        elif CostProfile.METERED in profiles and CostProfile.FREE not in profiles and CostProfile.UNKNOWN not in profiles:
            effective = CostProfile.METERED
        elif CostProfile.METERED in profiles:
            # Conservative: if a metered link is active alongside another link, treat as METERED unless overridden
            effective = CostProfile.METERED
        else:
            effective = CostProfile.UNKNOWN

        allow_unk = self.allow_external_lab_unknown if authorize_unknown is None else bool(authorize_unknown)
        allow_met = self.allow_metered if authorize_metered is None else bool(authorize_metered)

        if effective == CostProfile.METERED and not allow_met:
            return {
                "allowed": False,
                "requires_authorization": True,
                "effective_profile": effective.value,
                "cost_tier": COST_TIER_BY_PROFILE[effective],
                "reason": (
                    "External lab requires explicit authorization when cost profile is 'metered' "
                    "(authorize_metered=True not granted)"
                ),
            }

        if effective == CostProfile.UNKNOWN and not allow_unk:
            return {
                "allowed": False,
                "requires_authorization": True,
                "effective_profile": effective.value,
                "cost_tier": COST_TIER_BY_PROFILE[effective],
                "reason": (
                    "External lab requires explicit authorization when cost profile is 'unknown' "
                    "(authorize_unknown=True not granted and interface not configured as 'free')"
                ),
            }

        return {
            "allowed": True,
            "requires_authorization": False,
            "effective_profile": effective.value,
            "cost_tier": COST_TIER_BY_PROFILE[effective],
            "reason": None,
        }

    def remaining_budget_bytes(self) -> int:
        return max(0, self.max_session_bytes - self.bytes_consumed_total)

    def check_budget_for_transfer(self, requested_bytes: int) -> Dict[str, Any]:
        """Verifies a transfer fits within both single-test and cumulative session byte caps."""
        if requested_bytes < 0:
            raise ValueError("requested_bytes must be non-negative")
        if requested_bytes > self.max_single_test_bytes:
            return {
                "allowed": False,
                "approved_bytes": 0,
                "remaining_session_bytes": self.remaining_budget_bytes(),
                "reason": (
                    f"Requested {requested_bytes} B exceeds single-test limit "
                    f"({self.max_single_test_bytes} B)"
                ),
            }
        remaining = self.remaining_budget_bytes()
        if requested_bytes > remaining:
            return {
                "allowed": False,
                "approved_bytes": 0,
                "remaining_session_bytes": remaining,
                "reason": (
                    f"Requested {requested_bytes} B exceeds remaining session byte budget "
                    f"({remaining} B of {self.max_session_bytes} B)"
                ),
            }
        return {
            "allowed": True,
            "approved_bytes": requested_bytes,
            "remaining_session_bytes": remaining,
            "reason": None,
        }

    def record_consumption(self, num_bytes: int, ifname: Optional[str] = None) -> int:
        """Records actual bytes transferred during probes or speed tests."""
        delta = max(0, int(num_bytes))
        self.bytes_consumed_total += delta
        if ifname:
            self.bytes_by_interface[ifname] = self.bytes_by_interface.get(ifname, 0) + delta
        return self.bytes_consumed_total

    def reset_budget(self) -> None:
        self.bytes_consumed_total = 0
        self.bytes_by_interface.clear()
