from comfy import high

import re


@high(
    name="rule_cve202524471",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_wan1="show system interface wan1",
        show_wan2="show system interface wan2",
        show_ssl_vpn_settings="show vpn ssl settings",
        show_user_peer="show user peer",
        show_user_group="show user group",
    ),
)
def rule_cve202524471(configuration, commands, device, devices):
    """
    CVE-2025-24471 (Fortinet FortiOS) - Improper Certificate Validation (CWE-295)
    may allow an EAP verified remote user to connect from FortiClient via a revoked certificate.

    Advisory summary:
      - Affected:
          * FortiOS 7.6.0 through 7.6.1  (fixed in 7.6.2+)
          * FortiOS 7.4.0 through 7.4.7  (fixed in 7.4.8+)
      - Not affected: 7.2, 7.0, 6.4 (per advisory)

    Configuration exposure heuristic (best-effort, CLI-only):
      - Device is on an affected FortiOS train/version, AND
      - SSL-VPN is enabled/listening (common FortiClient remote access path), AND
      - There is evidence of certificate-based user auth being used for remote access
        (e.g., user peer / peer cert mapping present).

    Notes:
      - The CVE is about accepting revoked certificates during EAP-verified auth.
        Whether revocation checking is enabled/disabled is not reliably inferable from
        generic CLI output across deployments, so this rule uses a conservative
        "feature present" heuristic to avoid flagging devices that do not use
        FortiClient remote access with certificate auth at all.
      - If version cannot be parsed, return safe (do not assert).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-544
    """
    version_text = commands.show_version or ""

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - 'FortiOS v7.6.1,buildXXXX,...'
          - 'Version: 7.6.1'
        Return (major, minor, patch) as ints, or None.
        """
        patterns = [
            r"\bFortiOS\s+v(\d+)\.(\d+)\.(\d+)\b",
            r"\bVersion:\s*(\d+)\.(\d+)\.(\d+)\b",
            r"\bv(\d+)\.(\d+)\.(\d+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        """
        Per-train fixed versions (exclusive upper bound):
          - 7.6 fixed in 7.6.2 => vulnerable if 7.6.x and v < 7.6.2
          - 7.4 fixed in 7.4.8 => vulnerable if 7.4.x and v < 7.4.8
        Only trains explicitly listed as affected are considered.
        If unparseable, treat as safe.
        """
        v = _parse_version(text)
        if not v:
            return (False, None, None)

        fixed_by_train = {
            (7, 6): (7, 6, 2),
            (7, 4): (7, 4, 8),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return (False, v, None)

        return (v < fix, v, fix)

    version_vulnerable, v, fix = _is_version_vulnerable(version_text)
    if not version_vulnerable:
        return

    # --- Configuration heuristics (best-effort) ---
    ssl_settings = (commands.show_ssl_vpn_settings or "").lower()
    wan1 = (commands.show_wan1 or "").lower()
    wan2 = (commands.show_wan2 or "").lower()
    user_peer = (commands.show_user_peer or "").lower()
    user_group = (commands.show_user_group or "").lower()

    # SSL-VPN enabled heuristic:
    # Typical:
    #   config vpn ssl settings
    #       set status enable
    #       set port 443
    #   end
    ssl_vpn_enabled = "config vpn ssl settings" in ssl_settings and re.search(
        r"^\s*set\s+status\s+enable\b", ssl_settings, re.MULTILINE
    )

    # Also consider interface-level "ssl-vpn enable" (older/varies by config)
    # Typical:
    #   config system interface
    #       edit "wan1"
    #           set allowaccess ping https ssh fgfm ssl-vpn
    #       next
    allowaccess_ssl_vpn = any(
        re.search(r"^\s*set\s+allowaccess\b.*\bssl-vpn\b", txt, re.MULTILINE)
        for txt in (wan1, wan2)
    )

    ssl_vpn_listening = bool(ssl_vpn_enabled or allowaccess_ssl_vpn)

    # Certificate-based user auth heuristic:
    # Presence of "config user peer" indicates peer certificate mapping is configured.
    # Typical:
    #   config user peer
    #       edit "peer1"
    #           set ca "CA_Cert_1"
    #           set subject "CN=user1"
    #       next
    #   end
    cert_auth_configured = "config user peer" in user_peer and re.search(
        r"^\s*edit\s+\"?.+\"?\s*$", user_peer, re.MULTILINE
    )

    # Optional: if user peer is referenced by a group (not required, but strengthens signal)
    # Typical:
    #   config user group
    #       edit "ssl-vpn-users"
    #           set member "peer1" ...
    #       next
    #   end
    peer_referenced_in_group = ("config user group" in user_group) and (
        ("set member" in user_group and "peer" in user_group) or ("user peer" in user_group)
    )

    vulnerable_configuration = ssl_vpn_listening and (cert_auth_configured or peer_referenced_in_group)

    is_vulnerable = version_vulnerable and vulnerable_configuration

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-24471 (Fortinet FortiOS): "
        "Improper certificate validation (CWE-295) may allow an EAP verified remote user to connect from FortiClient "
        "using a revoked certificate. "
        f"Detected affected FortiOS version {'.'.join(map(str, v))} (fixed in {'.'.join(map(str, fix))}+ for this train) "
        "and configuration suggests FortiClient remote access with certificate-based authentication is in use "
        "(SSL-VPN enabled/listening and user peer/cert mapping present). "
        "Remediation: upgrade to FortiOS 7.6.2+ or 7.4.8+ as applicable and validate certificate revocation handling. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-544"
    )