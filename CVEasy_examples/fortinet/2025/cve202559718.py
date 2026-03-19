from comfy import high


@high(
    name="rule_cve202559718",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_global="show system global",
    ),
)
def rule_cve202559718(configuration, commands, device, devices):
    """
    CVE-2025-59718 (Fortinet FortiOS / FortiProxy / FortiSwitchManager) - FortiCloud SSO login authentication bypass
    via crafted SAML response (CWE-347: Improper Verification of Cryptographic Signature).

    Advisory summary:
      - An unauthenticated attacker may bypass FortiCloud SSO admin login authentication via a crafted SAML response
        message, if FortiCloud SSO admin login is enabled on the device.
      - FortiCloud SSO admin login is not enabled by default, but may be enabled during FortiCare registration unless
        explicitly disabled.

    Affected products / fixed versions (per Fortinet PSIRT FG-IR-25-647):
      - FortiOS:
          * 7.6.0-7.6.3  -> fixed in 7.6.4+
          * 7.4.0-7.4.8  -> fixed in 7.4.9+
          * 7.2.0-7.2.11 -> fixed in 7.2.12+
          * 7.0.0-7.0.17 -> fixed in 7.0.18+
      - FortiProxy:
          * 7.6.0-7.6.3  -> fixed in 7.6.4+
          * 7.4.0-7.4.10 -> fixed in 7.4.11+
          * 7.2.0-7.2.14 -> fixed in 7.2.15+
          * 7.0.0-7.0.21 -> fixed in 7.0.22+
      - FortiSwitchManager:
          * 7.2.0-7.2.6  -> fixed in 7.2.7+
          * 7.0.0-7.0.5  -> fixed in 7.0.6+

    Vulnerable configuration (exposure condition):
      - FortiCloud SSO admin login is enabled:
          config system global
              set admin-forticloud-sso-login enable
          end

    Non-vulnerable scenarios:
      - Device version is not in an affected train/range, OR
      - Version is affected but FortiCloud SSO admin login is disabled.

    Advisory:
      - https://www.fortiguard.com/psirt
        (PSIRT advisory: "Multiple Fortinet Products' FortiCloud SSO Login Authentication Bypass", FG-IR-25-647)
    """
    version_text = commands.show_version or ""
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        Extract (major, minor, patch) from typical Fortinet outputs, e.g.:
          - "FortiOS v7.4.8,build...."
          - "FortiProxy v7.2.14,build...."
          - "Version: 7.4.8"
        Returns tuple or None.
        """
        import re

        # Prefer explicit "Version: x.y.z"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # Common "vX.Y.Z" token
        m = re.search(r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _detect_product(text: str):
        """
        Best-effort product detection from 'get system status' output.
        Returns one of: 'fortios', 'fortiproxy', 'fortiswitchmanager', or None.
        """
        lt = text.lower()
        if "fortios" in lt or "fortigate" in lt:
            return "fortios"
        if "fortiproxy" in lt:
            return "fortiproxy"
        if "fortiswitchmanager" in lt:
            return "fortiswitchmanager"
        return None

    def _is_version_vulnerable(text: str):
        """
        Train-based matching:
          - Only trains explicitly listed as affected are considered.
          - If version cannot be parsed or product cannot be determined, return False (safe).
        """
        v = _parse_version(text)
        if not v:
            return False

        product = _detect_product(text)
        if not product:
            return False

        # Map: product -> {(major, minor): first_fixed_version}
        fixed = {
            "fortios": {
                (7, 6): (7, 6, 4),
                (7, 4): (7, 4, 9),
                (7, 2): (7, 2, 12),
                (7, 0): (7, 0, 18),
            },
            "fortiproxy": {
                (7, 6): (7, 6, 4),
                (7, 4): (7, 4, 11),
                (7, 2): (7, 2, 15),
                (7, 0): (7, 0, 22),
            },
            "fortiswitchmanager": {
                (7, 2): (7, 2, 7),
                (7, 0): (7, 0, 6),
            },
        }

        train = (v[0], v[1])
        product_fixed = fixed.get(product, {})
        if train not in product_fixed:
            return False  # train not listed as affected

        first_fixed = product_fixed[train]
        return v < first_fixed

    version_vulnerable = _is_version_vulnerable(version_text)

    # Vulnerable configuration: FortiCloud SSO admin login enabled
    # CLI knob per advisory:
    #   config system global
    #       set admin-forticloud-sso-login disable|enable
    #   end
    sso_enabled = "set admin-forticloud-sso-login enable" in global_text
    sso_disabled = "set admin-forticloud-sso-login disable" in global_text

    # If the setting is absent, treat as disabled (feature not enabled by default).
    sso_effectively_enabled = sso_enabled and not sso_disabled

    is_vulnerable = version_vulnerable and sso_effectively_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-59718 (Fortinet): FortiCloud SSO admin login authentication "
        "bypass via crafted SAML response due to improper verification of cryptographic signature (CWE-347). "
        "Detected an affected software version train (per FG-IR-25-647) and FortiCloud SSO admin login appears ENABLED "
        "('set admin-forticloud-sso-login enable'). "
        "Remediation: upgrade to a fixed release for your train (FortiOS 7.6.4+/7.4.9+/7.2.12+/7.0.18+, "
        "FortiProxy 7.6.4+/7.4.11+/7.2.15+/7.0.22+, FortiSwitchManager 7.2.7+/7.0.6+) and/or temporarily disable "
        "FortiCloud SSO admin login: "
        "config system global; set admin-forticloud-sso-login disable; end. "
        "Advisory: https://www.fortiguard.com/psirt"
    )