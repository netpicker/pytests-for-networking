from comfy import high


@high(
    name="rule_cve202564157",
    platform=["fortinet"],
    commands=dict(
        show_version="get system status",
        show_capwap="show wireless-controller wtp-profile",
        show_wireless_settings="show wireless-controller setting",
    ),
)
def rule_cve202564157(configuration, commands, device, devices):
    """
    CVE-2025-64157 (Fortinet FortiOS) - Externally-controlled format string in CLI (CAPWAP fast-failover mode) [CWE-134].

    Advisory summary:
      - Affected: FortiOS 7.6.0 through 7.6.4, 7.4.0 through 7.4.9, 7.2.0 through 7.2.11, 7.0 all versions
      - Impact: authenticated admin may execute unauthorized code or commands via specifically crafted configuration
      - Component: CLI
      - Condition: CAPWAP fast-failover mode configuration present/enabled (heuristic)

    Vulnerable scenario (heuristic):
      - Device runs an affected FortiOS version, AND
      - CAPWAP fast-failover mode appears enabled/configured in wireless controller settings or WTP profiles.

    Non-vulnerable scenarios:
      - FortiOS version is not in affected ranges, OR
      - Wireless controller / CAPWAP fast-failover is not enabled/configured (or wireless controller not in use).

    Advisory: https://fortiguard.com/psirt/FG-IR-25-795
    """
    version_output = (commands.show_version or "").lower()
    capwap_output = (commands.show_capwap or "").lower()
    wc_settings_output = (commands.show_wireless_settings or "").lower()

    def parse_version(text: str):
        # Tries to find "Version: x.y.z" or "FortiOS vx.y.z"
        import re

        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bfortios\s+v?([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if not m:
            return None
        return tuple(int(m.group(i)) for i in range(1, 4))

    def in_range(v, lo, hi):
        return v is not None and lo <= v <= hi

    v = parse_version(commands.show_version or "")

    # Affected:
    # - 7.6.0 .. 7.6.4
    # - 7.4.0 .. 7.4.9
    # - 7.2.0 .. 7.2.11
    # - 7.0.* (all versions) -> approximate as 7.0.0 .. 7.0.99
    version_vulnerable = any(
        [
            in_range(v, (7, 6, 0), (7, 6, 4)),
            in_range(v, (7, 4, 0), (7, 4, 9)),
            in_range(v, (7, 2, 0), (7, 2, 11)),
            in_range(v, (7, 0, 0), (7, 0, 99)),
        ]
    )

    # Configuration heuristic:
    # We look for CAPWAP fast-failover being enabled/configured.
    # FortiOS CLI varies; we match common tokens.
    capwap_fast_failover_enabled = any(
        token in capwap_output or token in wc_settings_output
        for token in [
            "set fast-failover enable",
            "set fast_failover enable",
            "set capwap-fast-failover enable",
            "set capwap_fast_failover enable",
        ]
    )

    # Safe configuration heuristic: explicit disable and no enable tokens.
    capwap_fast_failover_explicitly_disabled = (
        ("set fast-failover disable" in capwap_output or "set fast-failover disable" in wc_settings_output)
        or ("set fast_failover disable" in capwap_output or "set fast_failover disable" in wc_settings_output)
        or (
            "set capwap-fast-failover disable" in capwap_output
            or "set capwap-fast-failover disable" in wc_settings_output
        )
        or (
            "set capwap_fast_failover disable" in capwap_output
            or "set capwap_fast_failover disable" in wc_settings_output
        )
    ) and not capwap_fast_failover_enabled

    config_vulnerable = capwap_fast_failover_enabled and not capwap_fast_failover_explicitly_disabled

    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-64157 (Fortinet FortiOS): "
        "a use of externally-controlled format string vulnerability in the CLI (CAPWAP fast-failover mode) may allow an authenticated admin "
        "to execute unauthorized code or commands via specifically crafted configuration. "
        "Detected an affected FortiOS version (7.6.0-7.6.4, 7.4.0-7.4.9, 7.2.0-7.2.11, or 7.0.x) and CAPWAP fast-failover appears enabled/configured "
        "(matched tokens such as 'fast-failover' / 'set fast-failover enable' in wireless controller configuration output). "
        "Remediation: upgrade to a fixed release (7.6.5+, 7.4.10+, or migrate to a fixed release for 7.2/7.0) and/or disable CAPWAP fast-failover mode "
        "if not required. Advisory: https://fortiguard.com/psirt/FG-IR-25-795"
    )