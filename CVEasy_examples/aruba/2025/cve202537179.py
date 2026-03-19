from comfy import high


@high(
    name="rule_cve202537179",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web-server|https-server|http-server|mgmt|management|cli|ssh|telnet|api|papi|netconf|rest|snmp)",
    ),
)
def rule_cve202537179(configuration, commands, device, devices):
    """
    CVE-2025-37179 (HPESBNW04987 rev.2)

    Out-of-bounds read vulnerability leading to process crash / DoS in AOS-8 OS component
    handling certain data buffers. Advisory recommends restricting management interfaces
    (CLI and web-based management) to a dedicated L2 segment/VLAN and/or controlled by
    firewall policies.

    This rule flags devices that:
      1) Run a vulnerable AOS version (AOS-8.13.1.0 and below OR AOS-8.10.0.20 and below),
      AND
      2) Expose management services (web UI and/or CLI remote access) based on config hints.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04987"

    version_output = (commands.show_version or "").lower()

    def parse_version_from_show_version(text: str):
        # Accept common ArubaOS strings like:
        # "ArubaOS version 8.10.0.20"
        # "ArubaOS 8.13.1.0"
        import re

        m = re.search(r"\b(?:arubaos(?:\s+version)?\s+)?(\d+\.\d+\.\d+\.\d+)\b", text, re.IGNORECASE)
        return m.group(1) if m else None

    def ver_tuple(v: str):
        return tuple(int(x) for x in v.split("."))

    v = parse_version_from_show_version(commands.show_version or "")
    if not v:
        # If we cannot determine version, do not fail the device; treat as not evaluated.
        return

    vt = ver_tuple(v)

    # Vulnerable versions per advisory "Affected Software Version(s)" for AOS-8:
    # - AOS-8.13.x.x: 8.13.1.0 and below
    # - AOS-8.10.x.x: 8.10.0.20 and below
    # Note: Advisory mentions AOS-10 "might also be affected", but does not provide fixed versions.
    # This rule focuses on explicitly impacted AOS-8 ranges.
    vulnerable = False
    if vt[0] == 8:
        if vt[1] == 13 and vt <= ver_tuple("8.13.1.0"):
            vulnerable = True
        if vt[1] == 10 and vt <= ver_tuple("8.10.0.20"):
            vulnerable = True
        # EoM branches listed as affected (8.12, 8.11, 8.9, 8.8, 8.7, 8.6, 6.5.4) are also affected.
        if vt[1] in (12, 11, 9, 8, 7, 6):
            vulnerable = True
        if vt[0] == 6 and vt[1] == 5 and vt[2] == 4:
            vulnerable = True

    if not vulnerable:
        return

    # Configuration exposure check (best-effort):
    # Advisory mitigation: restrict CLI and web-based management interfaces.
    # We treat "vulnerable configuration" as management services enabled/exposed.
    mgmt_cfg_raw = (commands.show_mgmt_services or "").lower()
    mgmt_cfg = "\n".join(
        line for line in mgmt_cfg_raw.splitlines()
        if not line.strip().startswith("#") and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )

    web_enabled = any(
        token in mgmt_cfg
        for token in (
            "web-server",
            "https-server",
            "http-server",
            "webui",
            "web ui",
            "mgmt ui",
            "management ui",
        )
    )
    cli_remote_enabled = any(
        token in mgmt_cfg
        for token in (
            "ssh",
            "telnet",
            "cli",
            "netconf",
            "rest",
            "api",
            "papi",
        )
    )

    # If we cannot find any indication of management services, consider it "safe configuration"
    # per advisory workaround intent (restricted/disabled management exposure).
    vulnerable_configuration = web_enabled or cli_remote_enabled

    assert not vulnerable_configuration, (
        f"Device {device.name} is vulnerable to CVE-2025-37179 (Out-of-Bounds Read -> process crash/DoS). "
        f"Detected ArubaOS version {v} in an affected AOS-8 range, and management services appear enabled "
        f"(web_enabled={web_enabled}, cli_remote_enabled={cli_remote_enabled}). "
        f"Mitigation per advisory: restrict CLI and web-based management interfaces to a dedicated L2 segment/VLAN "
        f"and/or control via firewall policies. Advisory: {advisory_url}"
    )