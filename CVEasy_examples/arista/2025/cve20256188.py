from comfy import high
import re


@high(
    name="rule_cve20256188",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20256188(configuration, commands, device, devices):
    """
    CVE-2025-6188 (Arista EOS)

    Description:
      On affected platforms running Arista EOS, maliciously formed UDP packets with source port 3503
      may be accepted by EOS. UDP port 3503 is associated with LspPing Echo Reply. This can result in
      unexpected behaviors, especially for UDP-based services that do not perform some form of authentication.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (heuristics):
      - Device has an IP interface (L3) and is reachable (implicit for most deployments).
      - No explicit control-plane/ACL protection is present to drop UDP packets with source port 3503.
      - No explicit disabling of LSP ping / MPLS OAM features (if present) is configured.

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - Explicit ACL/CoPP/control-plane protection dropping UDP with source port 3503.
      - Device is L2-only with no IP interfaces (best-effort heuristic).
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

    # --- Configuration heuristics ---
    # 1) Determine if device is likely L3 (has any SVI or routed interface or ip routing enabled)
    l3_indicated = bool(
        re.search(r"^\s*ip routing\b", config_output, re.M | re.I)
        or re.search(r"^\s*interface\s+Vlan\d+\b", config_output, re.M | re.I)
        or re.search(r"^\s*interface\s+Management\d+\b", config_output, re.M | re.I)
        or re.search(r"^\s*ip address\b", config_output, re.M | re.I)
    )

    if not l3_indicated:
        # If it appears to be L2-only, treat as not vulnerable for this rule.
        assert True
        return

    # 2) Look for explicit protection that drops UDP packets with source port 3503.
    # We accept a few common patterns:
    # - "ip access-list ... deny udp any any eq 3503" (dest port)
    # - "ip access-list ... deny udp any eq 3503 any" (source port)
    # - "deny udp any any range 3503 3503" etc.
    # - "control-plane" / "copp" style ACLs are vendor/site specific; we just look for deny udp with 3503.
    acl_drops_3503 = bool(
        re.search(
            r"^\s*ip access-list\b[\s\S]*?\bdeny\s+udp\b[\s\S]*?\b3503\b",
            config_output,
            re.M | re.I,
        )
        or re.search(
            r"^\s*ipv6 access-list\b[\s\S]*?\bdeny\s+udp\b[\s\S]*?\b3503\b",
            config_output,
            re.M | re.I,
        )
        or re.search(
            r"^\s*mac access-list\b[\s\S]*?\bdeny\s+udp\b[\s\S]*?\b3503\b",
            config_output,
            re.M | re.I,
        )
    )

    # 3) Look for explicit disabling of LSP ping / MPLS OAM (best-effort; syntax may vary by EOS release).
    lsp_ping_disabled = bool(
        re.search(r"^\s*no\s+(mpls\s+)?lsp-ping\b", config_output, re.M | re.I)
        or re.search(r"^\s*no\s+mpls\s+oam\b", config_output, re.M | re.I)
        or re.search(r"^\s*no\s+mpls\s+ip\b", config_output, re.M | re.I)
    )

    # If either explicit drop or explicit disable is present, treat as mitigated.
    if acl_drops_3503 or lsp_ping_disabled:
        assert True
        return

    # Otherwise, treat as vulnerable (EOS 4.x + L3 + no explicit mitigation found).
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-6188. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected). "
        "This issue allows maliciously formed UDP packets with source port 3503 (LspPing Echo Reply) to be "
        "accepted by EOS, which can lead to unexpected behaviors, especially for UDP-based services lacking "
        "authentication. The running configuration indicates L3/IP is enabled, and no explicit mitigation was "
        "detected (no ACL/CoPP-style deny for UDP port 3503 and no explicit disabling of LSP ping/MPLS OAM). "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and/or implement control-plane or "
        "interface ACLs to drop UDP packets with source port 3503 (and/or disable LSP ping/MPLS OAM if unused). "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )