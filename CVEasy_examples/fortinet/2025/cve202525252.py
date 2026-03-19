from comfy import high


@high(
    name="rule_cve202525252",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_sslvpn_settings="show vpn ssl settings",
        show_sslvpn_portal="show vpn ssl web portal",
        show_user_saml="show user saml",
    ),
)
def rule_cve202525252(configuration, commands, device, devices):
    """
    CVE-2025-25252 (Fortinet FortiOS) - Insufficient Session Expiration in SSL-VPN using SAML authentication (CWE-613).

    Summary (Fortinet PSIRT, 2025-10-14):
      - FortiOS SSL-VPN with SAML authentication may allow re-opening/accessing a prior session by re-using a SAML record,
        even after the account was removed and the session terminated, if the attacker possesses the SAML record.

    Affected versions (per advisory):
      - FortiOS 7.6.0 through 7.6.2  (fixed in 7.6.3+)
      - FortiOS 7.4.0 through 7.4.6  (fixed in 7.4.7+)
      - FortiOS 7.2.0 through 7.2.10 (fixed in 7.2.11+)
      - FortiOS 7.0.0 through 7.0.16 (fixed in 7.0.17+)
      - FortiOS 6.4 all versions      (migrate to a fixed release)

    Vulnerable configuration (exposure heuristic):
      - Device runs an affected FortiOS version, AND
      - SSL-VPN is enabled/configured, AND
      - SAML authentication is configured for SSL-VPN (SAML IdP/SSO is in use).

    Non-vulnerable scenarios:
      - FortiOS version is at/above the fixed version for its train, OR
      - FortiOS version is not in an affected train, OR
      - SSL-VPN is not enabled/used, OR
      - SSL-VPN is used but SAML authentication is not configured.

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-487
    """
    import re

    version_text = commands.show_version or ""
    ssl_settings = (commands.show_sslvpn_settings or "").lower()
    ssl_portal = (commands.show_sslvpn_portal or "").lower()
    saml_text = (commands.show_user_saml or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - 'FortiOS v7.4.6,buildXXXX,...'
          - 'Version: 7.4.6'
        Return (major, minor, patch) as ints, or None if not parseable.
        """
        m = re.search(r"\bfortios\s+v(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = re.search(r"\bversion:\s*(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        """
        Train-based matching only for trains explicitly listed as affected.
        Return False (safe) if version cannot be parsed.
        """
        v = _parse_version(text)
        if not v:
            return False

        # first fixed version per affected train (major, minor) -> (major, minor, patch)
        fixed_by_train = {
            (7, 6): (7, 6, 3),
            (7, 4): (7, 4, 7),
            (7, 2): (7, 2, 11),
            (7, 0): (7, 0, 17),
            # 6.4 all versions affected; no fixed version in-train per advisory (must migrate)
            (6, 4): None,
        }

        train = (v[0], v[1])
        if train not in fixed_by_train:
            return False

        fix = fixed_by_train[train]
        if fix is None:
            return True  # all 6.4.* affected
        return v < fix  # affected "through X" => fixed at X, so vulnerable if below fix

    def _sslvpn_configured() -> bool:
        # Heuristic: presence of SSL-VPN settings/portal config indicates feature is configured.
        # Typical outputs include:
        #   config vpn ssl settings
        #   config vpn ssl web portal
        return ("config vpn ssl settings" in ssl_settings) or ("config vpn ssl web portal" in ssl_portal)

    def _saml_configured() -> bool:
        # Heuristic: SAML config exists (IdP/SSO) and/or SSL-VPN references SAML.
        # Typical outputs include:
        #   config user saml
        #   edit "AzureAD"
        #   set entity-id ...
        #   set single-sign-on-url ...
        # And SSL-VPN settings may reference SAML (varies by version), so also look for 'saml'.
        saml_objects_present = "config user saml" in saml_text and ("edit " in saml_text)
        ssl_mentions_saml = "saml" in ssl_settings or "saml" in ssl_portal
        return saml_objects_present or ssl_mentions_saml

    version_vulnerable = _is_version_vulnerable(version_text)
    config_vulnerable = _sslvpn_configured() and _saml_configured()
    is_vulnerable = version_vulnerable and config_vulnerable

    v = _parse_version(version_text)
    v_str = ".".join(str(x) for x in v) if v else "unparsed"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-25252 (Fortinet FortiOS SSL-VPN SAML): "
        "Insufficient session expiration may allow re-opening/accessing an SSL-VPN session via re-use of a SAML record "
        "(CWE-613). "
        f"Detected affected FortiOS version ({v_str}) and SSL-VPN appears configured with SAML authentication. "
        "Remediation: upgrade to FortiOS 7.6.3+/7.4.7+/7.2.11+/7.0.17+ as applicable, or migrate off 6.4; "
        "consider workaround: use FortiClient built-in browser for SAML auth and do not enable "
        "'Use external browser as user-agent for saml user authentication'. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-487"
    )