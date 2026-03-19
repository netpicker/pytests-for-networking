from comfy import high


@high(
    name="rule_cve202568686",
    platform=["fortinet"],
    commands=dict(
        show_version="get system status",
        show_sslvpn_settings="show vpn ssl settings",
    ),
)
def rule_cve202568686(configuration, commands, device, devices):
    """
    CVE-2025-68686 (Fortinet FortiOS) - SSL-VPN symlink persistence patch bypass (CWE-200).

    Summary (per Fortinet PSIRT FG-IR-25-934):
      - An unauthenticated remote attacker may bypass the patch developed for the SSL-VPN
        symbolic link persistency mechanism via crafted HTTP requests.
      - This can only be abused after a prior compromise that provides filesystem-level
        access (read-only) to the device.
      - Products that never had SSL-VPN enabled are not impacted.

    Affected versions:
      - FortiOS 7.6.0 through 7.6.1 (fixed in 7.6.2+)
      - FortiOS 7.4.0 through 7.4.6 (fixed in 7.4.7+)
      - FortiOS 7.2 all versions (migrate to a fixed release)
      - FortiOS 7.0 all versions (migrate to a fixed release)
      - FortiOS 6.4 all versions (migrate to a fixed release)

    Vulnerable scenario (heuristic):
      - Device runs an affected FortiOS version, AND
      - SSL-VPN is enabled (config 'show vpn ssl settings' contains 'set status enable').

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected range, OR
      - SSL-VPN is disabled ('set status disable' or no enable detected).

    Advisory: https://fortiguard.com/psirt/FG-IR-25-934
    """
    version_output = (commands.show_version or "").lower()
    sslvpn_output = (commands.show_sslvpn_settings or "").lower()

    def parse_version(text: str):
        # Try common FortiOS outputs: "Version: 7.4.6" or "FortiOS v7.4.6,..."
        import re

        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bfortios\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if not m:
            return None
        return tuple(int(x) for x in m.groups())

    def in_range(v, lo, hi):
        return v is not None and lo <= v <= hi

    v = parse_version(commands.show_version or "")

    # Version vulnerable if:
    # - 7.6.0-7.6.1
    # - 7.4.0-7.4.6
    # - any 7.2.x, 7.0.x, 6.4.x
    version_vulnerable = (
        in_range(v, (7, 6, 0), (7, 6, 1))
        or in_range(v, (7, 4, 0), (7, 4, 6))
        or (v is not None and v[0:2] in [(7, 2), (7, 0), (6, 4)])
        # Fallback: if parsing fails, do a conservative substring check for known affected trains.
        or (v is None and any(s in version_output for s in [" v7.6.0", " v7.6.1", " v7.4.", " v7.2.", " v7.0.", " v6.4."]))
    )

    # Configuration vulnerable if SSL-VPN is enabled.
    sslvpn_enabled = "set status enable" in sslvpn_output
    sslvpn_explicitly_disabled = "set status disable" in sslvpn_output and not sslvpn_enabled

    config_vulnerable = sslvpn_enabled and not sslvpn_explicitly_disabled

    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-68686 (Fortinet FortiOS): "
        "SSL-VPN symlink persistence patch bypass may allow exposure of sensitive information via crafted HTTP requests. "
        "Detected an affected FortiOS version (7.6.0-7.6.1, 7.4.0-7.4.6, or any 7.2/7.0/6.4) and SSL-VPN is enabled "
        "('set status enable' found in 'show vpn ssl settings'). "
        "Note: per advisory, exploitation requires prior filesystem-level compromise, and devices that never had SSL-VPN enabled are not impacted. "
        "Remediation: upgrade to FortiOS 7.6.2+ or 7.4.7+ (or migrate to a fixed release for 7.2/7.0/6.4) and consider disabling SSL-VPN if not needed. "
        "Advisory: https://fortiguard.com/psirt/FG-IR-25-934"
    )