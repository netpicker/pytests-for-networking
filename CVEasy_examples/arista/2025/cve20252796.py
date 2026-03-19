from comfy import high
import re


@high(
    name="rule_cve20252796",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20252796(configuration, commands, device, devices):
    """
    CVE-2025-2796 (Arista EOS)

    Description:
      On affected platforms with hardware IPSec support running Arista EOS with IPsec enabled and
      anti-replay protection configured, EOS may exhibit unexpected behavior in specific cases.
      Received duplicate encrypted packets, which should be dropped under normal anti-replay protection,
      will instead be forwarded due to this vulnerability.

      Note: this issue does not affect VXLANSec or MACSec encryption functionality.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (operational conditions):
      - IPsec is enabled/configured.
      - Anti-replay protection is configured/enabled for IPsec.
      - Device/platform has hardware IPsec support (not reliably detectable via config alone; this rule
        flags based on IPsec+anti-replay config and vulnerable version).

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - IPsec not configured.
      - IPsec configured but anti-replay not configured/enabled (best-effort heuristic).
      - VXLANSec/MACSec only (explicitly not affected).
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

    # --- Exclusions: VXLANSec / MACSec only (not affected) ---
    # If config indicates only MACSec/VXLANsec and no IPsec, treat as not vulnerable.
    macsec_present = bool(re.search(r"^\s*mac\s+security\b|^\s*macsec\b", config_output, re.M | re.I))
    vxlans_ec_present = bool(re.search(r"\bvxlans?ec\b|\bvxlan\s+security\b", config_output, re.I))

    # --- Vulnerable configuration heuristics: IPsec enabled + anti-replay configured ---
    # IPsec presence indicators (best-effort):
    # - "ip security" / "ipsec" / "crypto" / "isakmp" / "ike" / "tunnel protection ipsec"
    ipsec_configured = bool(
        re.search(r"\bipsec\b", config_output, re.I)
        or re.search(r"^\s*ip\s+security\b", config_output, re.M | re.I)
        or re.search(r"^\s*crypto\b", config_output, re.M | re.I)
        or re.search(r"\bikev?2?\b|\bisakmp\b", config_output, re.I)
        or re.search(r"tunnel\s+protection\s+ipsec", config_output, re.I)
    )

    if not ipsec_configured:
        # If only MACSec/VXLANSec is present, explicitly OK; otherwise OK due to no IPsec.
        assert True
        return

    # Anti-replay indicators (best-effort):
    # - "anti-replay" keyword
    # - "replay-window" / "replay window"
    # - "sequence-number" / "seq" related knobs (less reliable; keep conservative)
    anti_replay_configured = bool(
        re.search(r"\banti-?replay\b", config_output, re.I)
        or re.search(r"\breplay[- ]window\b", config_output, re.I)
    )

    if not anti_replay_configured:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-2796. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected), "
        "and configuration indicates IPsec is enabled with anti-replay protection configured. "
        "On affected hardware IPsec platforms, duplicate encrypted packets that should be dropped by "
        "anti-replay may instead be forwarded. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and/or disable IPsec anti-replay "
        "only if acceptable per security policy until upgraded. "
        "Note: VXLANSec and MACSec are not affected. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )