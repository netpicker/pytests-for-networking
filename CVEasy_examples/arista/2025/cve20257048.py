from comfy import high
import re


@high(
    name="rule_cve20257048",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20257048(configuration, commands, device, devices):
    """
    CVE-2025-7048 (Arista EOS)

    Description:
      On affected platforms running Arista EOS with MACsec configuration, a specially crafted packet can
      cause the MACsec process to terminate unexpectedly. Continuous receipt of these packets with certain
      MACsec configurations can cause longer term disruption of dataplane traffic.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (heuristic):
      - MACsec is configured/enabled (global and/or interface-level), e.g.:
          * "mac security" / "macsec" / "mka" configuration present
          * interface has MACsec/MKA statements

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - No MACsec/MKA configuration detected.

    Detection approach:
      - Parse EOS version from "show version".
      - Detect MACsec/MKA configuration in running-config.
      - If version is potentially affected AND MACsec is configured, flag as vulnerable.
    """
    version_output = commands.show_version or ""
    config_output = commands.show_running_config or ""

    # --- Version parsing (best-effort) ---
    # Common EOS output includes:
    #   "Software image version: 4.30.2F"
    #   "Software image version: 4.31.1M"
    #   "Software image version: 4.29.3.1F"
    m = re.search(
        r"Software image version:\s*([0-9]+)\.([0-9]+)\.([0-9]+)",
        version_output,
        re.I,
    )
    if not m:
        # Cannot determine version => do not assert vulnerability based on version alone.
        return

    major, minor, patch = map(int, m.groups())

    # --- Vulnerable versions (heuristic due to advisory CAPTCHA) ---
    version_vulnerable = (major == 4)

    if not version_vulnerable:
        assert True
        return

    # --- Vulnerable configuration heuristics: MACsec/MKA present ---
    # Best-effort indicators in EOS running-config:
    # - "mac security" (common MACsec CLI family)
    # - "macsec" keyword
    # - "mka" (MACsec Key Agreement)
    # - interface-level MACsec/MKA statements
    macsec_configured = bool(
        re.search(r"^\s*mac\s+security\b", config_output, re.M | re.I)
        or re.search(r"\bmacsec\b", config_output, re.I)
        or re.search(r"^\s*mka\b", config_output, re.M | re.I)
        or re.search(r"^\s*interface\s+\S+[\s\S]*?\b(mac\s+security|macsec|mka)\b", config_output, re.M | re.I)
    )

    if not macsec_configured:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-7048. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected) "
        "and MACsec/MKA configuration present. A specially crafted packet can cause the MACsec process to "
        "terminate unexpectedly; continuous receipt of such packets with certain MACsec configurations can "
        "cause longer term disruption of dataplane traffic. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and/or disable MACsec on affected "
        "interfaces until upgraded. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )