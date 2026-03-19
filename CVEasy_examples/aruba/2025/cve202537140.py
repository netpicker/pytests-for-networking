from comfy import high


@high(
    name="rule_cve202537140",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web-server|https-server|http-server|mgmt-server|management|ssh|telnet|netconf|rest|api|central)",
    ),
)
def rule_cve202537140(configuration, commands, device, devices):
    """
    CVE-2025-37140: Authenticated arbitrary file download vulnerability in the CLI binary
    of AOS-10 GW and AOS-8 Controller/Mobility Conductor operating systems.

    Practical exposure condition for a configuration-based compliance test:
      - Device is running an affected (vulnerable) AOS-10/AOS-8 version, AND
      - A remote management plane is enabled/reachable (e.g., SSH or Web UI), because exploitation
        requires an authenticated actor to access the management interfaces.

    Note: The advisory does not specify a single feature toggle that enables/disables the vulnerable
    code path beyond having authenticated access to management interfaces. This rule therefore treats
    "remote management enabled" as the vulnerable configuration condition.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").strip()

    # Determine if device is in an affected train and below fixed versions.
    # AOS-10 affected:
    #   - 10.7.2.0 and below (fixed: 10.7.2.1+)
    #   - 10.4.1.8 and below (fixed: 10.4.1.9+)
    # AOS-8 affected:
    #   - 8.13.0.1 and below (fixed: 8.13.1.0+)
    #   - 8.12.0.5 and below (fixed: 8.12.0.6+)
    #   - 8.10.0.18 and below (fixed: 8.10.0.19+)
    #
    # EoM branches are also affected (all versions), but we cannot reliably enumerate them from
    # "show version" without full parsing; we focus on the explicitly listed affected trains.
    vulnerable_versions = [
        # AOS-10 10.7.x.x
        "10.7.2.0",
        "10.7.1.0",
        "10.7.0.0",
        # AOS-10 10.4.x.x
        "10.4.1.8",
        "10.4.1.7",
        "10.4.1.6",
        "10.4.1.5",
        "10.4.1.4",
        "10.4.1.3",
        "10.4.1.2",
        "10.4.1.1",
        "10.4.1.0",
        "10.4.0.0",
        # AOS-8 8.13.x.x
        "8.13.0.1",
        "8.13.0.0",
        # AOS-8 8.12.x.x
        "8.12.0.5",
        "8.12.0.4",
        "8.12.0.3",
        "8.12.0.2",
        "8.12.0.1",
        "8.12.0.0",
        # AOS-8 8.10.x.x
        "8.10.0.18",
        "8.10.0.17",
        "8.10.0.16",
        "8.10.0.15",
        "8.10.0.14",
        "8.10.0.13",
        "8.10.0.12",
        "8.10.0.11",
        "8.10.0.10",
        "8.10.0.9",
        "8.10.0.8",
        "8.10.0.7",
        "8.10.0.6",
        "8.10.0.5",
        "8.10.0.4",
        "8.10.0.3",
        "8.10.0.2",
        "8.10.0.1",
        "8.10.0.0",
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_versions)
    if not version_vulnerable:
        return

    # Configuration exposure: management interfaces enabled (remote authenticated access path).
    mgmt_output = (commands.show_mgmt_services or "").lower()

    # Heuristic indicators that remote management is enabled.
    mgmt_indicators = [
        "ssh",
        "web-server",
        "https-server",
        "http-server",
        "mgmt-server",
        "management",
        "netconf",
        "rest",
        "api",
        "central",
        "telnet",
    ]
    mgmt_lines = [
        line for line in mgmt_output.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#")
    ]
    mgmt_output_filtered = "\n".join(mgmt_lines)
    mgmt_enabled = any(ind in mgmt_output_filtered for ind in mgmt_indicators)

    # If we cannot find any management indicators, treat as "safe configuration" for this test.
    if not mgmt_enabled:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37140 (authenticated arbitrary file download) "
        f"because it is running an affected ArubaOS AOS-10/AOS-8 version and has remote management "
        f"interfaces enabled, allowing an authenticated actor to potentially download arbitrary files "
        f"via carefully constructed exploits. Advisory: {advisory_url}"
    )