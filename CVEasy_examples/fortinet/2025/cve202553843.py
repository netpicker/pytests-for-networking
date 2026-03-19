from comfy import high


@high(
    name="rule_cve202553843",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_global="show system global",
        show_interfaces="show system interface",
        show_wtp="show wireless-controller wtp",
    ),
)
def rule_cve202553843(configuration, commands, device, devices):
    """
    CVE-2025-53843 (Fortinet FortiOS) - Stack-based buffer overflow in CAPWAP daemon (CWE-124).

    Advisory summary (Fortinet PSIRT, FG-IR-25-358):
      - A stack-based overflow in FortiOS (and FortiSwitchManager) CAPWAP daemon may allow a remote authenticated
        attacker to execute arbitrary code/commands as a low-privileged user via specially crafted packets.
      - Exploitation requires the attacker to pose as an authorized FortiAP or FortiExtender.
      - Warning: if "auto-auth-extension-device" is enabled on an interface, any device can be authorized and then
        the vulnerability can be exploited without administrator authorization.

    Affected FortiOS versions / fixed versions:
      - FortiOS 7.6.0 through 7.6.3  -> fixed in 7.6.4 (upgrade to 7.6.4+)
      - FortiOS 7.4.0 through 7.4.8  -> fixed in 7.4.9 (upgrade to 7.4.9+)
      - FortiOS 7.2 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiOS 7.0 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiOS 6.4 all versions     -> migrate to a fixed release (no fixed version specified in advisory)

    Vulnerable configuration (exposure heuristic):
      - Device runs an affected FortiOS train/version, AND
      - CAPWAP attack surface is plausibly enabled by either:
          * Security Fabric access enabled on any interface (workaround says to disable it), OR
          * auto-auth-extension-device enabled on any interface (explicit warning), OR
          * Wireless controller / managed FortiAPs configured (indicates CAPWAP usage).

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train, or is at/above the fixed version for 7.6/7.4, OR
      - Version cannot be parsed (rule returns safe), OR
      - Version is affected but CAPWAP exposure is not indicated by the above heuristics.
    """
    import re

    version_text = commands.show_version or ""
    global_text = (commands.show_global or "")
    interfaces_text = (commands.show_interfaces or "")
    wtp_text = (commands.show_wtp or "")

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - "FortiOS v7.6.3,buildxxxx,...."
          - "Version: 7.6.3"
        Return (major, minor, patch) as ints, or None.
        """
        m = re.search(r"\bFortiOS\s+v(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = re.search(r"\bVersion:\s*(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        v = _parse_version(text)
        if not v:
            return (False, None, None)

        # Per-train first fixed version (exclusive upper bound: v < fix is vulnerable).
        # Only trains explicitly listed in the advisory are included.
        fixed_by_train = {
            (7, 6): (7, 6, 4),  # 7.6.0-7.6.3 vulnerable
            (7, 4): (7, 4, 9),  # 7.4.0-7.4.8 vulnerable
            (7, 2): None,       # all versions affected (no fixed specified)
            (7, 0): None,       # all versions affected (no fixed specified)
            (6, 4): None,       # all versions affected (no fixed specified)
        }

        train = (v[0], v[1])
        if train not in fixed_by_train:
            return (False, v, None)

        fix = fixed_by_train[train]
        if fix is None:
            return (True, v, None)  # all versions in this train are affected per advisory
        return (v < fix, v, fix)

    version_vulnerable, parsed_v, fixed_v = _is_version_vulnerable(version_text)

    # Configuration / exposure heuristics based on advisory workarounds & prerequisites.
    # 1) Security Fabric access enabled on any interface.
    #    In config: "set allowaccess ... fabric" (or "securityfabric" on some builds).
    it_lower = interfaces_text.lower()
    fabric_access_enabled = bool(
        re.search(r"set\s+allowaccess\b[^\n]*\bfabric\b", it_lower)
        or re.search(r"set\s+allowaccess\b[^\n]*\bsecurityfabric\b", it_lower)
    )

    # 2) auto-auth-extension-device enabled on any interface (explicit warning).
    auto_auth_extension_enabled = bool(
        re.search(r"set\s+auto-auth-extension-device\s+enable\b", it_lower)
    )

    # 3) Wireless controller / managed FortiAPs present (CAPWAP usage indicator).
    #    Heuristic: presence of wireless-controller wtp config or any "edit" entries.
    wtp_lower = wtp_text.lower()
    managed_fortiap_configured = ("config wireless-controller wtp" in wtp_lower) and (
        re.search(r"^\s*edit\s+", wtp_lower, re.MULTILINE) is not None
    )

    config_exposed = fabric_access_enabled or auto_auth_extension_enabled or managed_fortiap_configured
    is_vulnerable = bool(version_vulnerable and config_exposed)

    advisory_url = "https://www.fortiguard.com/psirt/FG-IR-25-358"

    # If we cannot parse the version, treat as safe (per requirements).
    if parsed_v is None:
        return

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-53843 (Fortinet FortiOS): "
        "stack-based buffer overflow in the CAPWAP daemon may allow a remote authenticated attacker to execute "
        "unauthorized code/commands via specially crafted packets (CWE-124). "
        f"Detected affected FortiOS version {parsed_v[0]}.{parsed_v[1]}.{parsed_v[2]}"
        + (f" (first fixed: {fixed_v[0]}.{fixed_v[1]}.{fixed_v[2]})" if fixed_v else " (train affected: no fixed version specified in advisory)")
        + ". "
        "Exposure indicators found: "
        + ", ".join(
            s
            for s, ok in (
                ("Security Fabric access allowed on an interface (allowaccess fabric/securityfabric)", fabric_access_enabled),
                ("auto-auth-extension-device enabled on an interface", auto_auth_extension_enabled),
                ("Managed FortiAPs / wireless-controller WTP configuration present (CAPWAP in use)", managed_fortiap_configured),
            )
            if ok
        )
        + ". "
        "Remediation: upgrade to FortiOS 7.6.4+ (for 7.6) or 7.4.9+ (for 7.4), or migrate off affected 7.2/7.0/6.4 trains "
        "to a fixed release per Fortinet guidance. Workarounds: disable Security Fabric access on interfaces and only allow "
        "legitimate devices in WiFi Controller > Managed FortiAPs; ensure auto-auth-extension-device remains disabled. "
        f"Advisory: {advisory_url}"
    )