from comfy import high


@high(
    name="rule_cve202557740",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_vpn_ssl_settings="show vpn ssl settings",
        show_vpn_ssl_web_portal="show vpn ssl web portal",
    ),
)
def rule_cve202557740(configuration, commands, device, devices):
    """
    CVE-2025-57740 (Fortinet FortiOS / FortiProxy / FortiPAM) - Authenticated heap-based buffer overflow in SSL-VPN bookmarks (RDP).

    Advisory (Fortinet PSIRT):
      - "Authenticated Heap Overflow in SSL-VPN bookmarks"
      - RDP bookmark connection may allow an authenticated user to execute unauthorized code via crafted requests.

    Affected / fixed (FortiOS per advisory):
      - FortiOS 7.6.0 through 7.6.2  -> fixed in 7.6.3+
      - FortiOS 7.4.0 through 7.4.7  -> fixed in 7.4.8+
      - FortiOS 7.2.0 through 7.2.10 -> fixed in 7.2.11+
      - FortiOS 7.0 all versions     -> migrate to a fixed release (no fixed patch in-train)
      - FortiOS 6.4 all versions     -> migrate to a fixed release (no fixed patch in-train)

    Vulnerable configuration heuristic (FortiOS):
      - SSL-VPN is enabled, AND
      - At least one SSL-VPN web portal has an RDP bookmark configured (e.g., "set type rdp").

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train or is at/above the fixed version, OR
      - Version cannot be parsed (rule returns safe), OR
      - SSL-VPN is disabled, OR
      - No RDP bookmarks are configured in any SSL-VPN portal.

    Note:
      - This rule is written for FortiOS-style CLI outputs. FortiProxy/FortiPAM have different CLIs; this rule
        will conservatively return OK if it cannot confirm the vulnerable configuration.
    """
    version_text = commands.show_version or ""
    ssl_settings_text = (commands.show_vpn_ssl_settings or "").lower()
    portal_text = (commands.show_vpn_ssl_web_portal or "").lower()

    def _parse_version(text: str):
        """
        Fortinet version format: major.minor.patch[.build]
        Extract from common outputs like:
          - "FortiOS v7.4.7,buildxxxx,..."
          - "Version: 7.4.7"
        Returns (major, minor, patch) or None.
        """
        import re

        # Prefer explicit "Version: x.y.z"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # "FortiOS vX.Y.Z" (optionally followed by ",build...")
        m = re.search(r"\bforti\w*\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # Fallback: any standalone x.y.z (avoid matching build numbers by requiring dots)
        m = re.search(r"\b([0-9]+)\.([0-9]+)\.([0-9]+)\b", text)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching per advisory.
        Return False (safe) if version cannot be parsed.
        """
        v = _parse_version(text)
        if not v:
            return False, None

        major, minor, patch = v
        train = (major, minor)

        # Only trains explicitly listed as affected in the advisory.
        # Value is the first fixed version in that train, or None if "all versions" in that train are affected.
        fixed_by_train = {
            (7, 6): (7, 6, 3),
            (7, 4): (7, 4, 8),
            (7, 2): (7, 2, 11),
            (7, 0): None,  # all versions affected; migrate
            (6, 4): None,  # all versions affected; migrate
        }

        if train not in fixed_by_train:
            return False, v

        fixed = fixed_by_train[train]
        if fixed is None:
            return True, v  # all versions in-train affected
        return v < fixed, v

    version_vulnerable, parsed_version = _is_version_vulnerable(version_text)

    # Configuration checks (heuristics)
    # SSL-VPN enabled is typically:
    #   config vpn ssl settings
    #       set status enable
    #   end
    sslvpn_enabled = "set status enable" in ssl_settings_text

    # RDP bookmark in portal config typically includes:
    #   config vpn ssl web portal
    #       edit "full-access"
    #           config bookmark-group
    #               edit "default"
    #                   config bookmarks
    #                       edit "rdp1"
    #                           set type rdp
    #                       next
    #                   end
    #               next
    #           end
    #       next
    #   end
    has_rdp_bookmark = "set type rdp" in portal_text

    config_vulnerable = sslvpn_enabled and has_rdp_bookmark
    is_vulnerable = version_vulnerable and config_vulnerable

    advisory_url = "https://www.fortiguard.com/psirt/advisory/FG-IR-25-756"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-57740 (Fortinet): authenticated heap-based buffer overflow "
        "in SSL-VPN bookmarks (RDP) may allow an authenticated user to execute unauthorized code via crafted requests. "
        f"Detected affected FortiOS version ({'.'.join(map(str, parsed_version)) if parsed_version else 'unparsed'}), "
        "SSL-VPN appears enabled, and at least one SSL-VPN portal contains an RDP bookmark ('set type rdp'). "
        "Remediation: upgrade to a fixed release (FortiOS 7.6.3+/7.4.8+/7.2.11+) or migrate off affected 7.0/6.4 trains; "
        "as a mitigation, disable SSL-VPN or remove RDP bookmarks from SSL-VPN portals. "
        f"Advisory: {advisory_url}"
    )