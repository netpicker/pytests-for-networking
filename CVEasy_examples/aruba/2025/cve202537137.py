from comfy import high


@high(
    name="rule_cve202537137",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_access="show running-config | include (mgmt-user|aaa authentication|ssh|telnet|web-server|https|http|ip access-list|netservice|management)",
    ),
)
def rule_cve202537137(configuration, commands, device, devices):
    """
    CVE-2025-37137: Authenticated arbitrary file deletion in the AOS-8 Controller/Mobility Conductor CLI.
    Successful exploitation requires authenticated access to the CLI (remote).
    Advisory: HPESBNW04957 rev.1
    """
    version_output = (commands.show_version or "").lower()

    # Affected (vulnerable) AOS-8 versions per advisory:
    # - 8.13.0.1 and below
    # - 8.12.0.5 and below
    # - 8.10.0.18 and below
    # Fixed:
    # - 8.13.1.0 and above
    # - 8.12.0.6 and above
    # - 8.10.0.19 and above
    #
    # Note: Advisory also lists multiple EoM branches as affected; we cannot reliably enumerate all.
    vulnerable_markers = [
        "8.13.0.1",
        "8.13.0.0",
        "8.12.0.5",
        "8.12.0.4",
        "8.12.0.3",
        "8.12.0.2",
        "8.12.0.1",
        "8.12.0.0",
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
    fixed_markers = [
        "8.13.1.0",
        "8.13.1.1",
        "8.12.0.6",
        "8.12.0.7",
        "8.10.0.19",
        "8.10.0.20",
    ]

    # If we can positively identify a fixed version, treat as not vulnerable.
    if any(m in version_output for m in fixed_markers):
        return

    # If we cannot identify an affected version marker, do not flag.
    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        return

    # Configuration exposure: vulnerability requires authenticated remote CLI access.
    # Treat device as "exposed" if SSH or Telnet server is enabled in running config.
    mgmt_cfg = (commands.show_mgmt_access or "").lower()
    ssh_enabled = ("ssh" in mgmt_cfg) and ("no ssh" not in mgmt_cfg) and ("ssh disable" not in mgmt_cfg)
    telnet_enabled = ("telnet" in mgmt_cfg) and ("no telnet" not in mgmt_cfg) and ("telnet disable" not in mgmt_cfg)

    cli_remote_access_enabled = ssh_enabled or telnet_enabled

    assert not cli_remote_access_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37137 (AOS-8 CLI arbitrary file deletion). "
        f"The device appears to be running an affected ArubaOS 8 version and has remote CLI access enabled "
        f"(SSH/Telnet), which may allow an authenticated remote attacker to delete arbitrary files. "
        f"Upgrade to a fixed release (8.13.1.0+, 8.12.0.6+, or 8.10.0.19+) and/or restrict CLI access. "
        f"Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"
    )