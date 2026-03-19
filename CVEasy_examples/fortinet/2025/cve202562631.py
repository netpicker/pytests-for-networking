from comfy import high


@high(
    name="rule_cve202562631",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_sslvpn_settings="show vpn ssl settings",
        show_sslvpn_portal="show vpn ssl web portal",
    ),
)
def rule_cve202562631(configuration, commands, device, devices):
    """
    CVE-2025-62631 (Fortinet FortiOS) - Insufficient session expiration in SSL-VPN (CWE-613).

    Advisory summary:
      - FortiOS SSL-VPN may not terminate an active SSL-VPN session after a user's password change
        under particular conditions, allowing continued access via the existing session.

    Affected versions (per Fortinet PSIRT advisory FG-IR-25-411, published 2025-12-09):
      - FortiOS 7.4.0            (fixed in 7.4.1 and above)
      - FortiOS 7.2 all versions (migrate to a fixed release)
      - FortiOS 7.0 all versions (migrate to a fixed release)
      - FortiOS 6.4 all versions (migrate to a fixed release)
      - FortiOS 7.6 not affected

    Vulnerable configuration heuristic:
      - Device is running an affected FortiOS release train/version, AND
      - SSL-VPN is enabled (listening on an interface / enabled in settings), AND
      - At least one SSL-VPN portal exists (indicating SSL-VPN is in use).

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train, OR is at/above the fixed version for that train, OR
      - SSL-VPN is not enabled / not configured.

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-25-411
    """
    import re

    version_text = commands.show_version or ""
    settings_text = (commands.show_sslvpn_settings or "").lower()
    portal_text = (commands.show_sslvpn_portal or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - 'FortiOS v7.4.0,build...'
          - 'Version: 7.4.0'
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
        """
        Release-train based matching.

        Trains explicitly listed as affected in the advisory:
          - 6.4.x : all versions affected (no fixed version specified in advisory)
          - 7.0.x : all versions affected (no fixed version specified in advisory)
          - 7.2.x : all versions affected (no fixed version specified in advisory)
          - 7.4.x : only 7.4.0 affected; fixed in 7.4.1+

        Return (is_vuln: bool, parsed_version: tuple|None, reason: str)
        """
        v = _parse_version(text)
        if not v:
            return (False, None, "version_unparsed_treated_safe")

        major, minor, patch = v
        train = (major, minor)

        # Only include trains explicitly listed as affected.
        fixed_by_train = {
            (7, 4): (7, 4, 1),  # vulnerable if v < 7.4.1 (i.e., 7.4.0)
        }
        all_versions_affected_trains = {
            (6, 4),
            (7, 0),
            (7, 2),
        }

        if train in fixed_by_train:
            fix = fixed_by_train[train]
            return (v < fix, v, f"train_{major}.{minor}_fixed_in_{fix[0]}.{fix[1]}.{fix[2]}")
        if train in all_versions_affected_trains:
            return (True, v, f"train_{major}.{minor}_all_versions_affected")
        return (False, v, "train_not_listed_as_affected")

    def _sslvpn_enabled(settings: str):
        """
        Heuristic for SSL-VPN being enabled/configured.
        Typical snippets:
          config vpn ssl settings
              set status enable
              set source-interface "wan1"
          end
        """
        if "config vpn ssl settings" not in settings:
            return False
        if "set status enable" in settings:
            return True
        # Some outputs may omit explicit status; presence of source-interface is a strong indicator.
        if "set source-interface" in settings or "set source-interface6" in settings:
            return True
        return False

    def _sslvpn_portal_present(portal: str):
        """
        Heuristic for portal configuration existing.
        Typical snippets:
          config vpn ssl web portal
              edit "full-access"
              ...
              next
          end
        """
        if "config vpn ssl web portal" not in portal:
            return False
        return bool(re.search(r"^\s*edit\s+\".*?\"\s*$", portal, re.MULTILINE))

    version_vuln, parsed_v, version_reason = _is_version_vulnerable(version_text)

    sslvpn_on = _sslvpn_enabled(settings_text)
    portal_present = _sslvpn_portal_present(portal_text)

    config_vulnerable = sslvpn_on and portal_present
    is_vulnerable = version_vuln and config_vulnerable

    v_str = ".".join(str(x) for x in parsed_v) if parsed_v else "unparsed"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-62631 (Fortinet FortiOS SSL-VPN): "
        "insufficient session expiration (CWE-613) may allow an attacker to maintain access to network resources "
        "via an active SSL-VPN session that is not terminated after a user's password change under particular "
        "conditions. "
        f"Detected FortiOS version {v_str} ({version_reason}) and SSL-VPN appears enabled with at least one portal "
        "configured. Remediation: upgrade/migrate to a fixed FortiOS release (7.4.1+ for 7.4.x; migrate off 7.2/7.0/6.4 "
        "to a fixed release) and review SSL-VPN session management/operational procedures. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-25-411"
    )