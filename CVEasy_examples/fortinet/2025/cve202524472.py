from comfy import high


@high(
    name="rule_cve202524472",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_csf="show system csf",
    ),
)
def rule_cve202524472(configuration, commands, device, devices):
    """
    CVE-2025-24472 (Fortinet FortiOS / FortiProxy) - Authentication Bypass Using an Alternate Path or Channel (CWE-288)

    Summary (Fortinet PSIRT):
      - Affects FortiOS 7.0.0 through 7.0.16 and FortiProxy 7.2.0 through 7.2.12, 7.0.0 through 7.0.19.
      - May allow a remote unauthenticated attacker (with prior knowledge of upstream/downstream serial numbers)
        to gain super-admin privileges on the downstream device if Security Fabric is enabled, via crafted CSF proxy requests.

    Vulnerable when:
      - Device is in an affected release train/version range, AND
      - Security Fabric (CSF) is enabled.

    Non-vulnerable scenarios:
      - Device version is at/above the fixed version for its affected train, OR
      - Security Fabric (CSF) is disabled, OR
      - Version cannot be parsed (rule returns safe to avoid false positives).

    Advisory:
      - https://www.fortiguard.com/psirt
    """
    import re

    version_text = commands.show_version or ""
    csf_text = commands.show_csf or ""

    def _parse_version(text: str):
        """
        Extract Fortinet version as (major, minor, patch).
        Accepts common outputs like:
          - "FortiOS v7.0.16,buildxxxx"
          - "Version: 7.0.16"
          - "FortiProxy v7.2.12,buildxxxx"
        """
        patterns = [
            r"\bForti(?:OS|Proxy)\s+v(\d+)\.(\d+)\.(\d+)\b",
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
        Train-based matching using first fixed version (exclusive upper bound).
        Only trains explicitly listed as affected in the advisory are included.
        """
        v = _parse_version(text)
        if not v:
            return False

        # (major, minor) -> first fixed version (major, minor, patch)
        fixed_by_train = {
            # FortiOS 7.0: fixed in 7.0.17 (so < 7.0.17 is vulnerable)
            (7, 0): (7, 0, 17),
            # FortiProxy 7.2: fixed in 7.2.13
            (7, 2): (7, 2, 13),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return False

        return v < fix

    def _csf_enabled(text: str):
        """
        Heuristic: Security Fabric enabled if config shows 'set status enable'.
        Typical:
          config system csf
              set status enable
          end
        """
        t = (text or "").lower()
        # If we can see the knob explicitly disabled, treat as disabled.
        if re.search(r"\bset\s+status\s+disable\b", t):
            return False
        if re.search(r"\bset\s+status\s+enable\b", t):
            return True
        # If output doesn't include the knob, do not assume enabled.
        return False

    version_vuln = _is_version_vulnerable(version_text)
    if not version_vuln:
        return

    csf_is_enabled = _csf_enabled(csf_text)
    is_vulnerable = version_vuln and csf_is_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-24472 (Fortinet FortiOS/FortiProxy): "
        "an authentication bypass via crafted CSF proxy requests may allow a remote unauthenticated attacker "
        "to gain super-admin privileges on a downstream device when Security Fabric is enabled. "
        "Detected an affected 7.0/7.2 release-train version below the first fixed patch and CSF appears enabled. "
        "Remediation: upgrade FortiOS 7.0 to 7.0.17+; upgrade FortiProxy 7.2 to 7.2.13+ or FortiProxy 7.0 to 7.0.20+; "
        "or disable Security Fabric (config system csf -> set status disable). "
        "Advisory: https://www.fortiguard.com/psirt"
    )