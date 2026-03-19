from comfy import high


@high(
    name="rule_cve202525248",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_ssl_vpn_settings="show vpn ssl settings",
        show_ssl_vpn_portal="show vpn ssl web portal",
    ),
)
def rule_cve202525248(configuration, commands, device, devices):
    """
    CVE-2025-25248 (Fortinet FortiOS / FortiProxy / FortiPAM) - Integer Overflow/Wraparound in SSL-VPN RDP/VNC bookmarks (CWE-190).

    Summary (Fortinet PSIRT, 2025-08-12):
      - Integer Overflow or Wraparound in SSL-VPN RDP and VNC bookmarks may allow an authenticated user
        to affect SSL-VPN availability via crafted requests (DoS).

    Affected / fixed versions (per advisory):
      FortiOS:
        - 7.6.0 through 7.6.2  -> fixed in 7.6.3+
        - 7.4.0 through 7.4.7  -> fixed in 7.4.8+
        - 7.2.0 through 7.2.10 -> fixed in 7.2.11+
        - 7.0 all versions     -> migrate to a fixed release (no fixed version in-train stated)
        - 6.4 all versions     -> migrate to a fixed release (no fixed version in-train stated)
      FortiProxy / FortiPAM are also affected, but this rule targets FortiOS-style CLI outputs.

    Vulnerable configuration (exposure heuristic):
      - Device runs an affected FortiOS version, AND
      - SSL-VPN is enabled, AND
      - At least one SSL-VPN portal has RDP and/or VNC bookmarks enabled/configured.

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train/range, OR
      - SSL-VPN is disabled, OR
      - No portal enables RDP/VNC bookmarks (feature not in use).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-364
    """
    version_text = commands.show_version or ""
    ssl_settings_text = (commands.show_ssl_vpn_settings or "").lower()
    portal_text = (commands.show_ssl_vpn_portal or "").lower()

    def _parse_version(text: str):
        """
        Fortinet FortiOS commonly shows:
          - 'FortiOS v7.4.7,build....'
          - 'Version: 7.4.7'
        Return (major, minor, patch) or None.
        """
        import re

        patterns = [
            r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bfortios\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching:
          - For trains with a stated fixed version: vulnerable if v < fixed_version.
          - For trains stated as 'all versions': treat any parsed version in that train as vulnerable.
        If version cannot be parsed: return False (safe/unknown).
        """
        v = _parse_version(text)
        if not v:
            return False

        train = (v[0], v[1])

        fixed_by_train = {
            (7, 6): (7, 6, 3),
            (7, 4): (7, 4, 8),
            (7, 2): (7, 2, 11),
            # "all versions" trains (no fixed version in-train stated)
            (7, 0): None,
            (6, 4): None,
        }

        if train not in fixed_by_train:
            return False

        fixed = fixed_by_train[train]
        if fixed is None:
            return True
        return v < fixed

    def _ssl_vpn_enabled(settings_text: str):
        # Typical:
        #   config vpn ssl settings
        #       set status enable
        #   end
        return "set status enable" in settings_text

    def _rdp_vnc_bookmarks_in_use(portal_cfg_text: str):
        """
        Heuristic: detect RDP/VNC bookmark enablement in any portal.
        Common FortiOS portal options include:
          - 'set bookmark enable'
          - 'set rdp-bookmark enable' / 'set vnc-bookmark enable' (varies by version)
          - sections like 'config rdp-bookmark' / 'config vnc-bookmark'
        We treat presence of explicit enablement or bookmark config blocks as "in use".
        """
        indicators = (
            "set rdp-bookmark enable",
            "set vnc-bookmark enable",
            "config rdp-bookmark",
            "config vnc-bookmark",
            "set bookmark enable",
            "config bookmark",
        )
        return any(i in portal_cfg_text for i in indicators)

    v = _parse_version(version_text)
    version_vulnerable = _is_version_vulnerable(version_text)

    sslvpn_on = _ssl_vpn_enabled(ssl_settings_text)
    bookmarks_in_use = _rdp_vnc_bookmarks_in_use(portal_text)

    config_vulnerable = sslvpn_on and bookmarks_in_use
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-25248 (Fortinet FortiOS): "
        "Integer Overflow/Wraparound in SSL-VPN RDP/VNC bookmarks may allow an authenticated user to affect "
        "SSL-VPN availability (DoS) via crafted requests. "
        f"Detected affected FortiOS version ({'.'.join(map(str, v)) if v else 'unparsed'}), SSL-VPN is enabled, "
        "and SSL-VPN portal configuration indicates RDP/VNC bookmarks are enabled/configured. "
        "Remediation: upgrade to FortiOS 7.6.3+ / 7.4.8+ / 7.2.11+ (as applicable) or migrate off 7.0/6.4 trains; "
        "alternatively disable/remove SSL-VPN RDP/VNC bookmarks if not required. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-364"
    )