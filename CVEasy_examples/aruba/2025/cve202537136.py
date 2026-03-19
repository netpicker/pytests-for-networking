from comfy import high


@high(
    name="rule_cve202537136",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include \"ssh|telnet|web-server|https-server|mgmt-user\"",
    ),
)
def rule_cve202537136(configuration, commands, device, devices):
    """
    CVE-2025-37136: Authenticated arbitrary file deletion in the AOS-8 Controller/Mobility Conductor CLI.

    Advisory: HPESBNW04957 rev.1
    https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us
    """
    version_output = (commands.show_version or "").lower()
    mgmt_services = (commands.show_mgmt_services or "").lower()

    # AOS-8 affected branches and fixed versions per advisory:
    # - 8.13.0.1 and below (fixed in 8.13.1.0+)
    # - 8.12.0.5 and below (fixed in 8.12.0.6+)
    # - 8.10.0.18 and below (fixed in 8.10.0.19+)
    #
    # Note: Advisory also lists EoM branches as affected (e.g., 8.11.x, 8.9.x, 8.8.x, etc.).
    # This rule focuses on AOS-8 CLI exposure and version family detection from "show version".
    vulnerable_version_markers = [
        "arubaos version 8.13.0.1",
        "arubaos version 8.13.0.0",
        "arubaos version 8.12.0.5",
        "arubaos version 8.12.0.4",
        "arubaos version 8.12.0.3",
        "arubaos version 8.12.0.2",
        "arubaos version 8.12.0.1",
        "arubaos version 8.12.0.0",
        "arubaos version 8.10.0.18",
        "arubaos version 8.10.0.17",
        "arubaos version 8.10.0.16",
        "arubaos version 8.10.0.15",
        "arubaos version 8.10.0.14",
        "arubaos version 8.10.0.13",
        "arubaos version 8.10.0.12",
        "arubaos version 8.10.0.11",
        "arubaos version 8.10.0.10",
        "arubaos version 8.10.0.9",
        "arubaos version 8.10.0.8",
        "arubaos version 8.10.0.7",
        "arubaos version 8.10.0.6",
        "arubaos version 8.10.0.5",
        "arubaos version 8.10.0.4",
        "arubaos version 8.10.0.3",
        "arubaos version 8.10.0.2",
        "arubaos version 8.10.0.1",
        "arubaos version 8.10.0.0",
        # EoM branches (all affected per advisory; include common markers)
        "arubaos version 8.11.",
        "arubaos version 8.9.",
        "arubaos version 8.8.",
        "arubaos version 8.7.",
        "arubaos version 8.6.",
        "arubaos version 6.5.4.",
    ]

    version_vulnerable = any(m in version_output for m in vulnerable_version_markers)
    if not version_vulnerable:
        return

    # Vulnerable configuration: remote authenticated CLI access exposed (SSH/Telnet).
    # Advisory recommends restricting CLI/web management to dedicated VLAN/segments and firewall controls.
    # For a config-based test, treat "ssh enable" or "telnet enable" as exposure.
    cli_remote_enabled = any(
        token in mgmt_services
        for token in [
            "ssh enable",
            "telnet enable",
            "ip ssh",
            "ssh server",
            "telnet server",
        ]
    )

    # If CLI is not remotely enabled, treat as "safe configuration" for this test.
    if not cli_remote_enabled:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37136 (AOS-8 CLI arbitrary file deletion). "
        f"Detected vulnerable ArubaOS version from 'show version' and remote CLI access appears enabled "
        f"(SSH/Telnet). An authenticated remote actor could delete arbitrary files on the system. "
        f"Upgrade to a fixed release (8.13.1.0+, 8.12.0.6+, or 8.10.0.19+ as applicable) and restrict "
        f"management access to dedicated segments/VLANs with firewall controls. "
        f"Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"
    )