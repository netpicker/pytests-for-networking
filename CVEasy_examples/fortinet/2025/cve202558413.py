from comfy import high


@high(
    name="rule_cve202558413",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_wireless_controller="show wireless-controller setting",
        show_system_interface="show system interface",
        show_wireless_inter_controller="show wireless-controller inter-controller",
    ),
)
def rule_cve202558413(configuration, commands, device, devices):
    """
    CVE-2025-58413 (Fortinet FortiOS) - Stack-based buffer overflow in CAPWAP daemon (CWE-124).

    Advisory summary (Fortinet PSIRT, FG-IR-25-632):
      - A stack-based overflow in FortiOS CAPWAP daemon may allow a remote unauthenticated attacker
        on an adjacent network to achieve arbitrary code execution via specially crafted packets.
      - Default configuration note: attacker must be in control of an authorized FortiAP and be on
        the same local IP subnet. If "auto-auth-extension-device" is enabled, any device can be
        authorized without administrator authorization (disabled by default).
      - Workarounds:
          * Disable security fabric access into interface.
          * Only allow legit devices in Wifi Controller > Managed FortiAPs.
          * Remove inter-controller-peer elements in config wireless-controller inter-controller configuration.

    Affected / fixed versions (FortiOS):
      - 7.6.0 through 7.6.3  -> fixed in 7.6.4 (upgrade to 7.6.4+)
      - 7.4.0 through 7.4.8  -> fixed in 7.4.9 (upgrade to 7.4.9+)
      - 7.2 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - 7.0 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - 6.4 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - 6.2 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - 6.0 all versions     -> migrate to a fixed release (no fixed version specified in advisory)

    This rule is a configuration+version exposure heuristic:
      - Version must be affected, AND
      - CAPWAP/WiFi controller functionality appears enabled/configured, AND
      - Risk-increasing config is present (auto-auth-extension-device enabled OR inter-controller peers configured).

    If version cannot be parsed, rule returns safe (no finding) per requirements.
    """
    version_text = commands.show_version or ""
    wc_text = (commands.show_wireless_controller or "").lower()
    iface_text = (commands.show_system_interface or "").lower()
    interctl_text = (commands.show_wireless_inter_controller or "").lower()

    def _parse_version(text: str):
        import re

        # Common FortiOS outputs:
        #   "FortiOS v7.6.3,buildxxxx,..."
        #   "Version: 7.6.3"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        m = re.search(r"\bfortios\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        m = re.search(r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _is_version_vulnerable(text: str):
        v = _parse_version(text)
        if not v:
            return (False, None, None)

        # Per-train first fixed versions (exclusive upper bound: v < fix is vulnerable).
        # Only trains explicitly listed with a fixed version are included here.
        fixed_by_train = {
            (7, 6): (7, 6, 4),
            (7, 4): (7, 4, 9),
        }

        train = (v[0], v[1])
        if train in fixed_by_train:
            fix = fixed_by_train[train]
            return (v < fix, v, fix)

        # Trains listed as "all versions" affected (no fixed version specified in advisory).
        all_versions_affected_trains = {(7, 2), (7, 0), (6, 4), (6, 2), (6, 0)}
        if train in all_versions_affected_trains:
            return (True, v, None)

        return (False, v, None)

    version_vulnerable, parsed_v, fixed_v = _is_version_vulnerable(version_text)

    # Configuration heuristics:
    # - CAPWAP daemon is relevant when WiFi controller / FortiAP management is in use.
    # - Advisory notes exploitation typically requires an authorized FortiAP on same subnet.
    # - auto-auth-extension-device (on interfaces) can allow authorization without admin approval.
    # - inter-controller peers increase exposure surface per workaround guidance.
    wifi_controller_enabled = (
        ("config wireless-controller setting" in wc_text)
        and ("set status enable" in wc_text or "set status 'enable'" in wc_text)
    )
    wifi_controller_explicitly_disabled = "set status disable" in wc_text

    # Treat as in use if explicitly enabled, or if the block exists without an explicit disable.
    wifi_controller_present = "config wireless-controller setting" in wc_text
    wifi_controller_in_use = wifi_controller_enabled or (
        wifi_controller_present and not wifi_controller_explicitly_disabled
    )

    auto_auth_extension_enabled = "set auto-auth-extension-device enable" in iface_text
    inter_controller_peer_configured = (
        "config wireless-controller inter-controller" in interctl_text
        and ("set peer-ip" in interctl_text or "set peer" in interctl_text or "edit " in interctl_text)
    )

    config_vulnerable = wifi_controller_in_use and (auto_auth_extension_enabled or inter_controller_peer_configured)

    is_vulnerable = version_vulnerable and config_vulnerable

    fix_str = (
        f"{fixed_v[0]}.{fixed_v[1]}.{fixed_v[2]}+"
        if fixed_v
        else "a fixed release (per advisory: migrate to a fixed release)"
    )
    v_str = f"{parsed_v[0]}.{parsed_v[1]}.{parsed_v[2]}" if parsed_v else "unparsed"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-58413 (Fortinet FortiOS CAPWAP daemon stack overflow): "
        f"detected affected FortiOS version {v_str} and WiFi/CAPWAP controller appears in use, with additional "
        f"risk-increasing configuration present "
        f"({'auto-auth-extension-device enabled' if auto_auth_extension_enabled else ''}"
        f"{' and ' if (auto_auth_extension_enabled and inter_controller_peer_configured) else ''}"
        f"{'inter-controller peer configuration present' if inter_controller_peer_configured else ''}). "
        "An adjacent-network attacker may be able to achieve arbitrary code execution via specially crafted packets "
        "(default scenario requires control of an authorized FortiAP on the same subnet; enabling auto-auth-extension-device "
        "can allow authorization without administrator approval). "
        f"Remediation: upgrade FortiOS to {fix_str} for your train, and apply workarounds as applicable "
        "(disable security fabric access into interface; only allow legitimate FortiAPs; remove inter-controller peers). "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-25-632"
    )