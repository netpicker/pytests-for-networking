from comfy import high


@high(
    name="rule_cve202537157",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show running-config | include (https-server|web-management|rest|ssh|netconf|management)",
    ),
)
def rule_cve202537157(configuration, commands, device, devices):
    """
    CVE-2025-37157 - Authenticated Command Injection allows Unauthorized Command Execution in AOS-CX.

    Advisory: HPESBNW04888 rev.1 - HPE Aruba Networking AOS-CX Multiple Vulnerabilities
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04888en_us"

    version_output = (commands.show_version or "").strip()

    # Affected Products (per advisory):
    # 10.16.xxxx: 10.16.1000 and below
    # 10.15.xxxx: 10.15.1020 and below
    # 10.14.xxxx: 10.14.1050 and below
    # 10.13.xxxx: 10.13.1090 and below
    # 10.10.xxxx: 10.10.1160 and below
    vulnerable_versions = [
        # 10.16
        "10.16.1000",
        "10.16.0999",
        "10.16.0900",
        "10.16.0800",
        "10.16.0700",
        "10.16.0600",
        "10.16.0500",
        "10.16.0400",
        "10.16.0300",
        "10.16.0200",
        "10.16.0100",
        "10.16.0001",
        "10.16.0000",
        # 10.15
        "10.15.1020",
        "10.15.1010",
        "10.15.1000",
        "10.15.0900",
        "10.15.0800",
        "10.15.0700",
        "10.15.0600",
        "10.15.0500",
        "10.15.0400",
        "10.15.0300",
        "10.15.0200",
        "10.15.0100",
        "10.15.0000",
        # 10.14
        "10.14.1050",
        "10.14.1040",
        "10.14.1030",
        "10.14.1020",
        "10.14.1010",
        "10.14.1000",
        "10.14.0900",
        "10.14.0800",
        "10.14.0700",
        "10.14.0600",
        "10.14.0500",
        "10.14.0400",
        "10.14.0300",
        "10.14.0200",
        "10.14.0100",
        "10.14.0000",
        # 10.13
        "10.13.1090",
        "10.13.1080",
        "10.13.1070",
        "10.13.1060",
        "10.13.1050",
        "10.13.1040",
        "10.13.1030",
        "10.13.1020",
        "10.13.1010",
        "10.13.1000",
        "10.13.0900",
        "10.13.0800",
        "10.13.0700",
        "10.13.0600",
        "10.13.0500",
        "10.13.0400",
        "10.13.0300",
        "10.13.0200",
        "10.13.0100",
        "10.13.0000",
        # 10.10
        "10.10.1160",
        "10.10.1150",
        "10.10.1140",
        "10.10.1130",
        "10.10.1120",
        "10.10.1110",
        "10.10.1100",
        "10.10.1090",
        "10.10.1080",
        "10.10.1070",
        "10.10.1060",
        "10.10.1050",
        "10.10.1040",
        "10.10.1030",
        "10.10.1020",
        "10.10.1010",
        "10.10.1000",
        "10.10.0900",
        "10.10.0800",
        "10.10.0700",
        "10.10.0600",
        "10.10.0500",
        "10.10.0400",
        "10.10.0300",
        "10.10.0200",
        "10.10.0100",
        "10.10.0000",
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_versions)
    if not version_vulnerable:
        return

    # Vulnerable configuration (practical exposure):
    # The advisory states "authenticated remote attacker" and recommends restricting CLI and web-based
    # management interfaces. We treat enabled remote management services as increasing exposure.
    mgmt_output_raw = (commands.show_mgmt_services or "").lower()
    mgmt_output = "\n".join(
        line for line in mgmt_output_raw.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#")
    )

    remote_mgmt_enabled = any(
        token in mgmt_output
        for token in [
            "ssh server",
            "ssh",
            "https-server",
            "web-management",
            "rest",
            "netconf",
        ]
    )

    # If remote management is not enabled, treat as a safe configuration for this test rule.
    if not remote_mgmt_enabled:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37157. "
        "The device appears to be running an affected Aruba AOS-CX version per HPESBNW04888 "
        "and has remote management services enabled (e.g., SSH/HTTPS/REST/NETCONF), which increases "
        "exposure to authenticated command injection leading to potential RCE. "
        f"Advisory: {advisory_url}"
    )