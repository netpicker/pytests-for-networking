from comfy import high
import re


@high(
    name="rule_cve20252826",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20252826(configuration, commands, device, devices):
    """
    CVE-2025-2826 (Arista EOS)

    Description:
      On affected platforms running Arista EOS, ACL policies may not be enforced.
      IPv4 ingress ACL, MAC ingress ACL, or IPv6 standard ingress ACL enabled on one or more
      ethernet or LAG interfaces may result in ACL policies not being enforced for ingress packets.
      This can cause incoming packets to incorrectly be allowed or denied:
        * Packets which should be permitted may be dropped
        * Packets which should be dropped may be permitted

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a
      conservative heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (operational conditions):
      - One or more interfaces (Ethernet or Port-Channel/LAG) have an ingress ACL applied:
          * IPv4 ingress ACL (e.g., "ip access-group <ACL> in")
          * MAC ingress ACL (e.g., "mac access-group <ACL> in")
          * IPv6 standard ingress ACL (e.g., "ipv6 access-group <ACL> in")
      - The issue is about enforcement; presence of ingress ACL application is the key indicator.

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - No ingress ACL applied on any Ethernet/Port-Channel interface.
      - Unable to determine EOS version (rule will not assert vulnerability based on version alone).
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

    # --- Vulnerable configuration heuristics ---
    # Look for ingress ACL application under Ethernet/Port-Channel interfaces.
    # We consider any of these as "ingress ACL applied":
    #   ip access-group <name> in
    #   mac access-group <name> in
    #   ipv6 access-group <name> in
    #
    # We scope to interface blocks for Ethernet* and Port-Channel*.
    iface_blocks = re.findall(
        r"(?ms)^\s*interface\s+(Ethernet[^\n]*|Port-Channel[^\n]*)\n(.*?)(?=^\s*interface\s+|\Z)",
        config_output,
    )

    ingress_acl_hits = []
    for ifname, body in iface_blocks:
        if re.search(r"(?mi)^\s*ip\s+access-group\s+\S+\s+in\s*$", body):
            ingress_acl_hits.append((ifname.strip(), "ip access-group ... in"))
        if re.search(r"(?mi)^\s*mac\s+access-group\s+\S+\s+in\s*$", body):
            ingress_acl_hits.append((ifname.strip(), "mac access-group ... in"))
        if re.search(r"(?mi)^\s*ipv6\s+access-group\s+\S+\s+in\s*$", body):
            ingress_acl_hits.append((ifname.strip(), "ipv6 access-group ... in"))

    if not ingress_acl_hits:
        assert True
        return

    # Build a compact list of affected interfaces for the message
    affected = {}
    for ifname, kind in ingress_acl_hits:
        affected.setdefault(ifname, set()).add(kind)
    affected_str = ", ".join(
        f"{ifn}({'; '.join(sorted(kinds))})" for ifn, kinds in sorted(affected.items())
    )

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-2826. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected) and "
        f"ingress ACL(s) applied on interface(s): {affected_str}. "
        "On affected platforms, IPv4 ingress ACL, MAC ingress ACL, or IPv6 standard ingress ACL enabled on one "
        "or more Ethernet or LAG (Port-Channel) interfaces may not be enforced for ingress packets, causing "
        "packets that should be permitted to be dropped and/or packets that should be dropped to be permitted. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and validate ACL enforcement after upgrade. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )