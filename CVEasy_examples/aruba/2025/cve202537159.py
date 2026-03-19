from comfy import high


@high(
    name="rule_cve202537159",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_web_config="show running-config | include (https-server|http-server|web|rest|mgmt|management)",
    ),
)
def rule_cve202537159(configuration, commands, device, devices):
    """
    CVE-2025-37159: Authenticated Session Hijacking in AOS-CX web management interface.

    Advisory: HPESBNW04888 rev.1 - HPE Aruba Networking AOS-CX Multiple Vulnerabilities
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04888en_us"

    version_output = (commands.show_version or "").strip()
    web_cfg_raw = (commands.show_web_config or "").lower()
    web_cfg = "\n".join(
        line for line in web_cfg_raw.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#")
    )

    # Affected (vulnerable) versions per advisory:
    # 10.16.xxxx: 10.16.1000 and below  -> fixed in 10.16.1001+
    # 10.15.xxxx: 10.15.1020 and below  -> fixed in 10.15.1030+
    # 10.14.xxxx: 10.14.1050 and below  -> fixed in 10.14.1060+
    # 10.13.xxxx: 10.13.1090 and below  -> fixed in 10.13.1101+
    # 10.10.xxxx: 10.10.1160 and below  -> fixed in 10.10.1170+
    vulnerable_versions = [
        "10.16.1000",
        "10.15.1020",
        "10.14.1050",
        "10.13.1090",
        "10.10.1160",
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_versions)
    if not version_vulnerable:
        return

    # Workaround in advisory: temporarily disable the web management interface.
    # We treat "web mgmt enabled" as vulnerable configuration.
    # Heuristic: if config output indicates http/https server enabled, consider web mgmt enabled.
    web_mgmt_enabled = any(
        token in web_cfg
        for token in [
            "https-server enable",
            "http-server enable",
            "https server enable",
            "http server enable",
            "web-management enable",
            "web management enable",
            "web ui enable",
            "rest interface enable",
            "rest enable",
        ]
    )

    assert not web_mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37159 (AOS-CX authenticated session hijacking) "
        f"because it is running an affected AOS-CX version (matched: {', '.join([v for v in vulnerable_versions if v in version_output])}) "
        f"and the web management interface appears to be enabled. "
        f"An authenticated attacker may hijack an active user session and view/modify sensitive configuration data. "
        f"Apply the vendor fix (upgrade to a fixed release) or disable the web management interface as a workaround. "
        f"Advisory: {advisory_url}"
    )