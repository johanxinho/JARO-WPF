"""JARO WPF - Network Interface & Metered State Monitor (Phase 3).

Detects:
- Interface additions, removals, link disconnections, and reconnections.
- IPv4/IPv6 address roaming changes.
- OS-level metered hints (NetworkManager GENERAL.METERED & USB tethering heuristics).
- Manual user overrides for interface data cost without assuming Ethernet is free.
"""
from datetime import datetime, timezone
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional

from core.connection.analyzer import get_interfaces
from core.connection.cost_manager import CostManager, CostProfile
from core.connection.multi_method_manager import classify_interface_medium


def query_nmcli_metered_hint(ifname: str) -> Optional[bool]:
    """Queries NetworkManager (if present on Linux) to detect metered Wi-Fi or USB tethering."""
    nmcli_bin = shutil.which("nmcli")
    if not nmcli_bin or not ifname:
        return None
    try:
        res = subprocess.run(
            [nmcli_bin, "-t", "-f", "GENERAL.METERED", "dev", "show", ifname],
            capture_output=True,
            text=True,
            timeout=1.5,
        )
        if res.returncode != 0:
            return None
        out = res.stdout.lower()
        if "yes" in out:
            return True
        if "no" in out:
            return False
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def is_likely_usb_tethering(ifname: str) -> bool:
    """Detects Linux systemd predictable USB network interface names (e.g., iPhone/Android USB tether)."""
    lower = ifname.lower()
    if lower.startswith(("usb", "ipheth", "rndis")):
        return True
    # e.g., enp0s20f0u1 (PCI bus + USB port suffix 'u<N>')
    if lower.startswith("enp") and "u" in lower[3:]:
        return True
    return False


class NetworkMonitor:
    """Tracks live network interfaces, transitions (disconnect/reconnect), and cost profiles."""

    def __init__(
        self,
        cost_manager: Optional[CostManager] = None,
        interface_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        metered_hint_provider: Optional[Callable[[str], Optional[bool]]] = None,
    ) -> None:
        self.cost_manager = cost_manager or CostManager()
        self._interface_provider = interface_provider or get_interfaces
        self._metered_hint_provider = metered_hint_provider or query_nmcli_metered_hint
        self._previous_snapshot: Dict[str, Dict[str, Any]] = {}
        self._was_online: Optional[bool] = None
        self.events_log: List[Dict[str, Any]] = []

    def set_interface_cost(
        self,
        ifname: str,
        profile: CostProfile | str,
        persist: bool = False,
    ) -> CostProfile:
        """Allows the user to manually mark any interface as FREE, METERED, or UNKNOWN."""
        resolved = self.cost_manager.set_interface_profile(ifname, profile, persist=persist)
        if ifname in self._previous_snapshot:
            old_prof = self._previous_snapshot[ifname].get("cost_profile")
            if old_prof != resolved.value:
                self._record_event(
                    "COST_PROFILE_CHANGED",
                    interface=ifname,
                    details={"from": old_prof, "to": resolved.value},
                )
                self._previous_snapshot[ifname]["cost_profile"] = resolved.value
        return resolved

    def _record_event(self, event_type: str, interface: Optional[str], details: Dict[str, Any]) -> Dict[str, Any]:
        ev = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "interface": interface,
            "details": details,
        }
        self.events_log.append(ev)
        return ev

    def scan_interfaces(self) -> Dict[str, Any]:
        """Captures current interfaces, classifies media & cost profiles, and computes change events."""
        raw_list = self._interface_provider()
        current_map: Dict[str, Dict[str, Any]] = {}

        for item in raw_list:
            name = item.get("name") or ""
            if not name or name == "lo":
                continue

            raw_state = (item.get("state") or "UNKNOWN").upper()
            addrs = sorted(item.get("addresses") or [])
            is_up = raw_state in ("UP", "UNKNOWN") and len(addrs) > 0

            meta = classify_interface_medium(name)
            medium = meta["medium"]

            os_metered = self._metered_hint_provider(name)
            if os_metered is None and is_likely_usb_tethering(name):
                os_metered = True

            cost_profile = self.cost_manager.classify_interface(
                ifname=name,
                medium=medium,
                os_metered_hint=os_metered,
            )

            current_map[name] = {
                "name": name,
                "state": raw_state,
                "is_online": is_up,
                "addresses": addrs,
                "medium": medium,
                "os_metered_hint": os_metered,
                "cost_profile": cost_profile.value,
                "metered": cost_profile == CostProfile.METERED,
            }

        delta_events = self._compute_transitions(self._previous_snapshot, current_map)
        self._previous_snapshot = current_map

        active_interfaces = [iface for iface in current_map.values() if iface["is_online"]]
        gate = self.cost_manager.evaluate_network_gate(active_interfaces)

        return {
            "online": len(active_interfaces) > 0,
            "active_interfaces": active_interfaces,
            "all_interfaces": list(current_map.values()),
            "cost_gate": gate,
            "events": delta_events,
        }

    def _compute_transitions(
        self,
        prev: Dict[str, Dict[str, Any]],
        curr: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []

        for name, c_info in curr.items():
            if name not in prev:
                events.append(
                    self._record_event(
                        "INTERFACE_ADDED",
                        interface=name,
                        details={
                            "medium": c_info["medium"],
                            "is_online": c_info["is_online"],
                            "cost_profile": c_info["cost_profile"],
                            "addresses": c_info["addresses"],
                        },
                    )
                )
                continue

            p_info = prev[name]
            if not p_info["is_online"] and c_info["is_online"]:
                events.append(
                    self._record_event(
                        "LINK_RECONNECTED",
                        interface=name,
                        details={"addresses": c_info["addresses"], "cost_profile": c_info["cost_profile"]},
                    )
                )
            elif p_info["is_online"] and not c_info["is_online"]:
                events.append(
                    self._record_event(
                        "LINK_DISCONNECTED",
                        interface=name,
                        details={"previous_state": p_info["state"], "current_state": c_info["state"]},
                    )
                )
            elif p_info["addresses"] != c_info["addresses"]:
                events.append(
                    self._record_event(
                        "IP_ADDRESS_CHANGED",
                        interface=name,
                        details={"from": p_info["addresses"], "to": c_info["addresses"]},
                    )
                )

            if p_info["cost_profile"] != c_info["cost_profile"]:
                events.append(
                    self._record_event(
                        "COST_PROFILE_CHANGED",
                        interface=name,
                        details={"from": p_info["cost_profile"], "to": c_info["cost_profile"]},
                    )
                )

        for name, p_info in prev.items():
            if name not in curr:
                events.append(
                    self._record_event(
                        "INTERFACE_REMOVED",
                        interface=name,
                        details={"was_online": p_info["is_online"]},
                    )
                )

        now_online = any(i["is_online"] for i in curr.values())
        if self._was_online is True and not now_online:
            events.append(self._record_event("ALL_NETWORKS_DISCONNECTED", interface=None, details={}))
        elif self._was_online is False and now_online:
            events.append(self._record_event("NETWORK_CONNECTIVITY_RESTORED", interface=None, details={}))
        self._was_online = now_online

        return events
