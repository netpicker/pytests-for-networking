from comfy import high
import re


@high(
    name="rule_cve20258872",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20258872(configuration, commands, device, devices):
    """
    CVE-2025-8872 (Arista EOS)

    Description:
      On affected platforms running Arista EOS with OSPFv3 configured, a specially crafted packet can cause
      the OSPFv3 process to have high CPU utilization which may result in the OSPFv3 process being restarted.
      This may cause disruption in the OSPFv3 routes on the switch.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (for this rule):
      - OSPFv3 is configured/enabled (presence of "router ospfv3" and at least one interface participating
        via "ipv6 ospf area ..." or "ospfv3 area ...").

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - OSPFv3 not configured.
      - OSPFv3 router stanza exists but no interface participation detected (best-effort).
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
        return

    # --- Vulnerable configuration heuristics: OSPFv3 configured and active on at least one interface ---
    # Router stanza
    ospfv3_router_present = bool(
        re.search(r"^\s*router\s+ospfv3\b", config_output, re.M | re.I)
    )

    if not ospfv3_router_present:
        return

    # Interface participation indicators (best-effort):
    # - "ipv6 ospf area <id>" (common EOS syntax)
    # - "ipv6 ospfv3 area <id>" or "ipv6 ospf3 area <id>" (variants)
    # - "ospfv3 area <id>" (some syntaxes)
    ospfv3_interface_participation = bool(
        re.search(r"^\s*ipv6\s+ospf(v3|3)?\s+area\s+\S+", config_output, re.M | re.I)
        or re.search(r"^\s*ospfv3\s+area\s+\S+", config_output, re.M | re.I)
    )

    if not ospfv3_interface_participation:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-8872. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected) "
        "with OSPFv3 configured and enabled on at least one interface. A specially crafted packet may cause "
        "high CPU utilization in the OSPFv3 process, potentially leading to an OSPFv3 process restart and "
        "disruption of OSPFv3 routing. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and/or disable OSPFv3 where not needed "
        "until upgraded. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )