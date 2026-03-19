from comfy import high


@high(
    name="rule_cve202525250",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_sslvpn_settings="show vpn ssl settings",
        show_sslvpn_portal="show vpn ssl web portal",
    ),
)
def rule_cve202525250(configuration, commands, device, devices):
    """
    CVE-2025-25250 (Fortinet FortiOS) - Information disclosure on SSL-VPN web-mode (CWE-200).

    Summary (Fortinet PSIRT, 2025-06-10):
      - FortiOS SSL-VPN web-mode may allow an authenticated user to access full SSL-VPN settings via crafted URL.

    Affected versions (per advisory):
      - FortiOS 7.6: 7.6.0 (fixed in 7.6.1+)
      - FortiOS 7.4: 7.4.0 through 7.4.7 (fixed in 7.4.8+)
      - FortiOS 7.2: all versions (migrate to a fixed release)
      - FortiOS 7.0: all versions (migrate to a fixed release)
      - FortiOS 6.4: all versions (migrate to a fixed release)

    Vulnerable configuration heuristic:
      - Device runs an affected FortiOS version, AND
      - SSL-VPN is enabled, AND
      - At least one SSL-VPN web-mode portal exists (web-mode feature in use).

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train or is at/above the fixed version for that train, OR
      - SSL-VPN is disabled, OR
      - No web-mode portal is configured (web-mode not in use).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-257
    """
    import re

    version_text = commands.show_version or ""
    settings_text = (commands.show_sslvpn_settings or "").lower()
    portal_text = (commands.show_sslvpn_portal or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - "FortiOS v7.4.7,build...."
          - "Version: 7.4.7"
        Return (major, minor, patch) as ints, or None if not parseable.
        """
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
            # Per requirements: if we cannot parse, return early and treat as safe.
            return (False, None, None)

        major, minor, patch = v
        train = (major, minor)

        # Per-train first fixed version (exclusive upper bound: v < fix is vulnerable).
        # Only include trains explicitly listed as affected in the advisory.
        fixed_by_train = {
            (7, 6): (7, 6, 1),  # 7.6.0 fixed in 7.6.1+
            (7, 4): (7, 4, 8),  # 7.4.0-7.4.7 fixed in 7.4.8+
        }

        if train in fixed_by_train:
            fix = fixed_by_train[train]
            return (v < fix, v, fix)

        # "All versions" affected for these trains (no fixed version given in advisory).
        all_versions_affected_trains = {(7, 2), (7, 0), (6, 4)}
        if train in all_versions_affected_trains:
            return (True, v, None)

        return (False, v, None)

    version_vulnerable, parsed_v, fixed_v = _is_version_vulnerable(version_text)

    # SSL-VPN enabled heuristic:
    # Typical output:
    #   config vpn ssl settings
    #       set status enable
    #   end
    sslvpn_enabled = "set status enable" in settings_text

    # Web-mode portal present heuristic:
    # Typical output:
    #   config vpn ssl web portal
    #       edit "full-access"
    #           set web-mode enable
    #       next
    #   end
    has_any_portal = "config vpn ssl web portal" in portal_text and "edit " in portal_text
    web_mode_enabled_somewhere = "set web-mode enable" in portal_text

    web_mode_in_use = has_any_portal and web_mode_enabled_somewhere

    config_vulnerable = sslvpn_enabled and web_mode_in_use
    is_vulnerable = version_vulnerable and config_vulnerable

    fix_str = (
        f"fixed in {fixed_v[0]}.{fixed_v[1]}.{fixed_v[2]}+"
        if fixed_v
        else "no fixed version in this train per advisory (migrate to a fixed release)"
    )
    detected_str = (
        f"{parsed_v[0]}.{parsed_v[1]}.{parsed_v[2]}" if parsed_v else "unparsed"
    )

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-25250 (Fortinet FortiOS): "
        "FortiOS SSL-VPN web-mode may allow an authenticated user to access full SSL-VPN settings via crafted URL "
        "(CWE-200). "
        f"Detected affected FortiOS version {detected_str} ({fix_str}). "
        "SSL-VPN appears enabled and at least one SSL-VPN web-mode portal is configured/enabled. "
        "Remediation: upgrade/migrate to a fixed FortiOS release per Fortinet guidance (7.6.1+, 7.4.8+, or migrate "
        "off 7.2/7.0/6.4 trains) and review SSL-VPN exposure. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-257"
    )