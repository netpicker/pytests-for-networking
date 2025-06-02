from comfy import high


@high(
    name='rule_cve202324547',
    platform=['arista_mos'],
    commands=dict(
        show_version='show version',
        show_bgp_config='show running-config | section router bgp'
    ),
)
def rule_cve202324547(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24547 vulnerability in Arista MOS devices.
    The vulnerability exposes BGP passwords in clear text in logs and running configuration,
    which could allow authenticated users to view sensitive password information.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # MOS versions from 0.13.0 through 0.39.4
        '0.13.0', '0.34.0',
        '0.35.3',
        '0.36.0', '0.36.9',
        '0.37.0', '0.37.1',
        '0.38.0', '0.38.1',
        '0.39.0', '0.39.1', '0.39.2', '0.39.3', '0.39.4'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check BGP configuration for plaintext passwords
    bgp_config = commands.show_bgp_config

    # Look for BGP neighbor password configurations without type 7 encryption
    has_plaintext_password = False
    for line in bgp_config.splitlines():
        if 'neighbor' in line and 'password' in line and 'key 7' not in line:
            has_plaintext_password = True
            break

    # Assert that the device is not vulnerable
    assert not has_plaintext_password, (
        f"Device {device.name} is vulnerable to CVE-2023-24547. "
        "The device is running a vulnerable version of MOS AND has BGP neighbors configured "
        "with plaintext passwords, which could expose sensitive information in logs and running config. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * MOS-0.39.4 or later for 0.39.x train\n"
        "  * MOS-0.36.10 or later for 0.36.x train\n"
        "2. After upgrading, passwords will be automatically obfuscated with type-7 encryption\n"
        "3. It is recommended to rotate BGP passwords after upgrading since they may have been exposed\n"
        "Note: Only MOS-0.39.x and MOS-0.36.x trains are currently under maintenance support.\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/18644-security-advisory-0090"
    )
