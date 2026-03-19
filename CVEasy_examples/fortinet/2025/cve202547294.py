from comfy import high


@high(
    name="rule_cve202547294",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_fabric="show system csf",
        show_global="show system global",
    ),
)
def rule_cve202547294(configuration, commands, device, devices):
    """
    CVE-2025-47294 (Fortinet FortiOS) - Denial of Service in Security Fabric Root (csfd crash) via integer overflow/wraparound (CWE-190).

    Advisory summary (Fortinet PSIRT, 2025-05-13):
      - An integer overflow or wraparound in FortiOS Security Fabric may allow a remote unauthenticated attacker
        to crash the csfd daemon via a specially crafted request.

    Affected versions / fixed versions:
      - FortiOS 7.2.0 through 7.2.7  -> fixed in 7.2.8 and above
      - FortiOS 7.0.0 through 7.0.14 -> fixed in 7.0.15 and above
      - FortiOS 7.4 / 7.6: not affected (per advisory)
      - FortiOS 6.4: "all versions" (advisory says migrate to a fixed release; no fixed version provided)

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected FortiOS release train/version, AND
      - Security Fabric / CSF is enabled (device participates in Security Fabric / has a Security Fabric root).

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train/range, OR
      - FortiOS version is affected but Security Fabric/CSF is disabled (reduces exposure to this component), OR
      - Version cannot be parsed (rule returns safe/OK by requirement).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-388
    """
    version_text = commands.show_version or ""
    csf_text = (commands.show_fabric or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version format: major.minor.patch[.build]
        Return (major, minor, patch) as ints, or None if not parseable.
        """
        import re

        # Common outputs:
        #   "FortiOS v7.2.7,buildXXXX,..."
        #   "Version: 7.2.7"
        m = re.search(r"\bFortiOS\s+v(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bVersion:\s*(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bv(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def _is_version_vulnerable(text: str):
        """
        Train-based matching only for trains explicitly listed as affected in the advisory.
        Uses first fixed version as exclusive upper bound: v < fixed.
        Returns (bool, parsed_version_tuple_or_None, fixed_tuple_or_None)
        """
        v = _parse_version(text)
        if not v:
            return (False, None, None)

        # Only include trains explicitly listed as affected with known fixed versions.
        fixed_by_train = {
            (7, 2): (7, 2, 8),
            (7, 0): (7, 0, 15),
        }

        train = (v[0], v[1])
        fixed = fixed_by_train.get(train)
        if not fixed:
            return (False, v, None)

        return (v < fixed, v, fixed)

    version_vulnerable, v, fixed = _is_version_vulnerable(version_text)

    # Configuration heuristic: Security Fabric / CSF enabled.
    # Typical snippets:
    #   config system csf
    #       set status enable
    #       set group-name "..."
    #       set group-password ENC ...
    #   end
    #
    # Some versions may show "set status enable" or "set status disable".
    csf_config_present = "config system csf" in csf_text
    csf_enabled = ("set status enable" in csf_text) or ("set status enable" in global_text)
    csf_disabled = ("set status disable" in csf_text) or ("set status disable" in global_text)

    # If CSF config is present and explicitly enabled -> enabled.
    # If explicitly disabled -> disabled.
    # If absent/unknown -> treat as not enabled (conservative to avoid false positives).
    csf_effectively_enabled = bool(csf_config_present and csf_enabled and not csf_disabled)

    is_vulnerable = bool(version_vulnerable and csf_effectively_enabled)

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-47294 (Fortinet FortiOS): an integer overflow/wraparound "
        "(CWE-190) in Security Fabric may allow a remote unauthenticated attacker to crash the csfd daemon via a "
        "specially crafted request (DoS). "
        f"Detected affected FortiOS version {'.'.join(map(str, v)) if v else 'unparsed'}"
        f"{' (< ' + '.'.join(map(str, fixed)) + ')' if fixed else ''} and Security Fabric/CSF appears enabled "
        "('config system csf' with 'set status enable'). "
        "Remediation: upgrade to FortiOS 7.2.8+ (for 7.2) or 7.0.15+ (for 7.0), or disable Security Fabric/CSF if not "
        "required until upgrade can be performed. Advisory: https://www.fortiguard.com/psirt/FG-IR-24-388"
    )