from comfy import high


@high(
    name="rule_cve202525249",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_interfaces="show system interface",
        show_local_in_policy="show firewall local-in-policy",
        show_custom_services="show firewall service custom",
    ),
)
def rule_cve202525249(configuration, commands, device, devices):
    """
    CVE-2025-25249 (Fortinet FortiOS / FortiSwitchManager) - Heap-based buffer overflow in cw_acd daemon (CWE-122).

    Fortinet PSIRT advisory (FG-IR-25-084):
      - A heap-based buffer overflow in cw_acd daemon may allow a remote unauthenticated attacker to execute
        arbitrary code/commands via specifically crafted requests/packets.
      - Exposure is tied to CAPWAP-CONTROL (UDP 5246-5249) reachability, typically when an interface allows "fabric"
        access (Security Fabric / CAPWAP control plane).

    Affected / fixed versions (FortiOS):
      - 7.6.0 through 7.6.3  -> fixed in 7.6.4+
      - 7.4.0 through 7.4.8  -> fixed in 7.4.9+
      - 7.2.0 through 7.2.11 -> fixed in 7.2.12+
      - 7.0.0 through 7.0.17 -> fixed in 7.0.18+
      - 6.4.0 through 6.4.16 -> migrate to a fixed release (treat < 6.4.17 as vulnerable; advisory notes 6.4.17 removed)

    Workarounds (exposure reduction):
      - Remove "fabric" from interface allowaccess, OR
      - Block CAPWAP-CONTROL UDP 5246-5249 via local-in policy (allow only trusted CAPWAP devices, deny others).

    This rule flags vulnerability when:
      - FortiOS version is in an affected train AND below the first fixed version, AND
      - At least one interface has "set allowaccess ... fabric ...", AND
      - There is no explicit local-in-policy deny for UDP/5246-5249 (CAPWAP-CONTROL) (heuristic).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-25-084
    """
    version_text = commands.show_version or ""
    interfaces_text = (commands.show_interfaces or "").lower()
    local_in_text = (commands.show_local_in_policy or "").lower()
    custom_svc_text = (commands.show_custom_services or "").lower()

    def _parse_version(text: str):
        import re

        # Common FortiOS outputs:
        #   "FortiOS v7.4.8,build...."
        #   "Version: 7.4.8"
        #   "FortiOS 7.4.8"
        patterns = [
            r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bfortios\s+v?([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        v = _parse_version(text)
        if not v:
            # Per requirements: if we cannot parse, return early and treat as safe.
            return (False, None, None)

        # Only trains explicitly listed as affected in the advisory.
        # Map (major, minor) -> first fixed version (exclusive upper bound: v < fixed is vulnerable).
        fixed_by_train = {
            (7, 6): (7, 6, 4),
            (7, 4): (7, 4, 9),
            (7, 2): (7, 2, 12),
            (7, 0): (7, 0, 18),
            (6, 4): (6, 4, 17),  # advisory: "6.4.0 through 6.4.16"; 6.4.17 removed from fixed list
        }

        train = (v[0], v[1])
        fixed = fixed_by_train.get(train)
        if not fixed:
            return (False, v, None)

        return (v < fixed, v, fixed)

    def _has_fabric_allowaccess(intf_text: str) -> bool:
        # Heuristic: any interface stanza contains "set allowaccess" with token "fabric".
        # Example:
        #   config system interface
        #       edit "port1"
        #           set allowaccess fabric ssh https
        #       next
        return "set allowaccess" in intf_text and " fabric" in intf_text

    def _capwap_control_blocked(local_in: str, custom_svc: str) -> bool:
        """
        Heuristic for workaround presence:
          - If local-in-policy contains an explicit deny for UDP 5246-5249 (either via a custom service
            or direct port range), consider CAPWAP-CONTROL blocked.
        """
        # If there is no local-in-policy at all, assume not blocked.
        if "config firewall local-in-policy" not in local_in and "local-in-policy" not in local_in:
            return False

        # Look for deny action and either:
        #  - service "capwap-control" (custom service name from advisory), OR
        #  - udp-portrange 5246-5249 referenced in custom service and used in local-in-policy, OR
        #  - direct mention of 5246-5249 in local-in-policy output (some outputs inline ports)
        deny_present = "set action deny" in local_in or "\naction deny" in local_in

        if not deny_present:
            return False

        # Service name path
        if "capwap-control" in local_in:
            return True

        # Port-range path: custom service defines udp-portrange 5246-5249 and local-in-policy references that service
        has_udp_range = "udp-portrange 5246-5249" in custom_svc or "udp-portrange 5246 5249" in custom_svc
        if has_udp_range and ("set service" in local_in or "service " in local_in):
            # If local-in-policy denies something and custom service exists, treat as blocked.
            return True

        # Direct port mention in local-in-policy output
        if "5246-5249" in local_in or "5246" in local_in and "5249" in local_in:
            return True

        return False

    version_vuln, parsed_v, fixed_v = _is_version_vulnerable(version_text)
    fabric_exposed = _has_fabric_allowaccess(interfaces_text)
    capwap_blocked = _capwap_control_blocked(local_in_text, custom_svc_text)

    config_vuln = fabric_exposed and (not capwap_blocked)
    is_vulnerable = version_vuln and config_vuln

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-25249 (Fortinet FortiOS): heap-based buffer overflow in "
        "cw_acd daemon may allow remote unauthenticated code/command execution via crafted CAPWAP control traffic. "
        f"Detected affected FortiOS version {parsed_v} (fixed in {fixed_v}+ for this train), and configuration appears "
        "exposed: at least one interface allows 'fabric' access and no local-in-policy workaround blocking "
        "CAPWAP-CONTROL (UDP 5246-5249) was detected. Remediation: upgrade to a fixed release and/or remove 'fabric' "
        "from interface allowaccess, or block UDP 5246-5249 with local-in-policy (allow only trusted CAPWAP devices, "
        "deny all others). Advisory: https://www.fortiguard.com/psirt/FG-IR-25-084"
    )