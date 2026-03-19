from comfy import high

@high(
    name='rule_cve202537177',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_mgmt_services='show configuration | include "mgmt-server|web-server|ssh|telnet|https|http|netconf|api|papi|enable"'
    ),
)
def rule_cve202537177(configuration, commands, device, devices):
    """
    CVE-2025-37177: Authenticated arbitrary file deletion vulnerability in the ArubaOS CLI
    for Mobility Conductors running AOS-8 or AOS-10.

    This rule flags devices that are:
      1) Running a vulnerable AOS-8/AOS-10 version per advisory, AND
      2) Expose remote CLI access (e.g., SSH/Telnet) via management services configuration.

    Advisory: HPESBNW04987 rev.2
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04987en_us"

    version_output = (commands.show_version or "")
    mgmt_output = (commands.show_mgmt_services or "")

    # Determine if the device is running a vulnerable version based on advisory fixed versions:
    # Fixed: AOS-10.7.2.2+, AOS-10.4.1.10+, AOS-8.13.1.1+, AOS-8.10.0.21+
    # Vulnerable: AOS-10.7.2.1 and below; AOS-10.4.1.9 and below; AOS-8.13.1.0 and below; AOS-8.10.0.20 and below
    vulnerable_versions = [
        # AOS-10.7.x.x vulnerable up to 10.7.2.1
        '10.7.2.1', '10.7.2.0',
        # AOS-10.4.x.x vulnerable up to 10.4.1.9
        '10.4.1.9', '10.4.1.8', '10.4.1.7', '10.4.1.6', '10.4.1.5',
        '10.4.1.4', '10.4.1.3', '10.4.1.2', '10.4.1.1', '10.4.1.0',
        # AOS-8.13.x.x vulnerable up to 8.13.1.0
        '8.13.1.0',
        # AOS-8.10.x.x vulnerable up to 8.10.0.20
        '8.10.0.20', '8.10.0.19', '8.10.0.18', '8.10.0.17', '8.10.0.16',
        '8.10.0.15', '8.10.0.14', '8.10.0.13', '8.10.0.12', '8.10.0.11',
        '8.10.0.10', '8.10.0.9', '8.10.0.8', '8.10.0.7', '8.10.0.6',
        '8.10.0.5', '8.10.0.4', '8.10.0.3', '8.10.0.2', '8.10.0.1',
        '8.10.0.0',
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_versions)
    if not version_vulnerable:
        return

    # Configuration condition: vulnerability is in CLI; exploitation requires authenticated remote access.
    # Treat device as "exposed" if remote CLI services appear enabled (SSH/Telnet).
    mgmt_lower = mgmt_output.lower()
    # Filter out negated/disabled lines before checking for enabled services.
    mgmt_lines_filtered = [
        line for line in mgmt_lower.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#") and "disable" not in line
    ]
    mgmt_filtered = "\n".join(mgmt_lines_filtered)
    remote_cli_enabled = (
        ('ssh' in mgmt_filtered and 'enable' in mgmt_filtered) or
        ('telnet' in mgmt_filtered and 'enable' in mgmt_filtered) or
        ('mgmt-server' in mgmt_filtered and 'ssh' in mgmt_filtered) or
        ('mgmt-server' in mgmt_filtered and 'telnet' in mgmt_filtered)
    )

    assert not remote_cli_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37177 (Authenticated Arbitrary File Deletion in ArubaOS CLI). "
        f"The device appears to be running a vulnerable ArubaOS version and has remote CLI access enabled (e.g., SSH/Telnet), "
        f"which increases exposure to authenticated remote exploitation. "
        f"Upgrade to a fixed release (AOS-10 10.7.2.2+/10.4.1.10+ or AOS-8 8.13.1.1+/8.10.0.21+) and restrict management access. "
        f"Advisory: {advisory_url}"
    )