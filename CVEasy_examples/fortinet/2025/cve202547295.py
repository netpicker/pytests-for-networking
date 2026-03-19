from comfy import high


@high(
    name="rule_cve202547295",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_fgfm="get system global | grep -i fgfm",
    ),
)
def rule_cve202547295(configuration, commands, device, devices):
    """
    CVE-2025-47295 (Fortinet FortiOS) - Buffer over-read in FGFM may allow remote unauthenticated DoS (crash fgfmd).

    Advisory summary:
      - A buffer over-read (CWE-126) in FortiOS FGFM may allow a remote unauthenticated attacker to crash the FGFM daemon
        via a specially crafted request, under rare conditions outside of the attacker's control.

    Affected versions / fixed versions (per Fortinet PSIRT):
      - FortiOS 7.4.0 through 7.4.3  -> fixed in 7.4.4+
      - FortiOS 7.2.0 through 7.2.7  -> fixed in 7.2.8+
      - FortiOS 7.0.0 through 7.0.14 -> fixed in 7.0.15+
      - FortiOS 7.6: not affected

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected FortiOS version, AND
      - FGFM is enabled/listening (FortiGate-to-FortiGate Management / FortiManager protocol).
        This is approximated by checking for explicit FGFM enablement in system global output.
        (If we cannot determine FGFM state, we treat it as safe to avoid false positives.)

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train, OR
      - FortiOS version is at/above the fixed version for its train, OR
      - FGFM appears disabled (or cannot be confirmed enabled by available CLI output).

    Advisory:
      - https://www.fortiguard.com/psirt
    """

    version_text = commands.show_version or ""
    fgfm_text = (commands.show_fgfm or "").lower()

    def _parse_version(text: str):
        """
        Extract FortiOS version as (major, minor, patch).
        Accepts patterns like:
          - "FortiOS v7.2.7,build..."
          - "Version: 7.2.7"
          - "v7.2.7"
        """
        import re

        patterns = [
            r"\bfortios\s+v(\d+)\.(\d+)\.(\d+)\b",
            r"\bversion:\s*(\d+)\.(\d+)\.(\d+)\b",
            r"\bv(\d+)\.(\d+)\.(\d+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        """
        Train-based matching only for trains explicitly listed as affected in the advisory.
        Returns (is_vulnerable: bool, parsed_version: tuple|None, fixed_version: tuple|None)
        """
        v = _parse_version(text)
        if not v:
            return (False, None, None)

        # Keyed by (major, minor) -> first fixed version (major, minor, patch)
        fixed_by_train = {
            (7, 4): (7, 4, 4),
            (7, 2): (7, 2, 8),
            (7, 0): (7, 0, 15),
        }

        fix = fixed_by_train.get((v[0], v[1]))
        if not fix:
            return (False, v, None)

        return (v < fix, v, fix)

    version_vulnerable, v, fix = _is_version_vulnerable(version_text)

    # Configuration heuristic: FGFM enabled.
    # Common knobs include:
    #   set fgfm-enable enable|disable
    # Some platforms may not show this line; in that case we avoid flagging.
    fgfm_enabled = "set fgfm-enable enable" in fgfm_text
    fgfm_disabled = "set fgfm-enable disable" in fgfm_text
    fgfm_state_known = ("set fgfm-enable" in fgfm_text) or fgfm_enabled or fgfm_disabled

    config_vulnerable = fgfm_enabled if fgfm_state_known else False
    is_vulnerable = bool(version_vulnerable and config_vulnerable)

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-47295 (Fortinet FortiOS): "
        "a buffer over-read in FGFM may allow a remote unauthenticated attacker to crash the FGFM daemon (DoS) via a "
        "specially crafted request (rare conditions). "
        f"Detected affected FortiOS version {'.'.join(map(str, v))} in train {v[0]}.{v[1]} "
        f"(fixed in {'.'.join(map(str, fix))}+), and FGFM appears enabled. "
        "Remediation: upgrade to FortiOS 7.4.4+ / 7.2.8+ / 7.0.15+ as applicable, or disable FGFM if not needed. "
        "Advisory: https://www.fortiguard.com/psirt"
    )