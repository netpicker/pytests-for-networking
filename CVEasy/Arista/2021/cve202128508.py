from comfy import high


@high(
    name='rule_cve202128508',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_terminattr='show running-config | include terminattr',
        show_ipsec='show running-config | section crypto ipsec'
    ),
)
def rule_cve202128508(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28508 vulnerability in Arista EOS devices.
    The vulnerability allows TerminAttr to leak IPsec sensitive data in clear text to CVP,
    which could allow authorized users to decrypt or modify IPsec traffic.
    """
    # Extract the version information from the command output
    version_output = str(commands.show_version)

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.23.x versions before 4.23.11
        '4.23.0', '4.23.1', '4.23.2', '4.23.3', '4.23.4', '4.23.5',
        '4.23.6', '4.23.7', '4.23.8', '4.23.9', '4.23.10',
        # 4.24.x versions before 4.24.10
        '4.24.0', '4.24.1', '4.24.2', '4.24.3', '4.24.4', '4.24.5',
        '4.24.6', '4.24.7', '4.24.8', '4.24.9',
        # 4.25.x versions before 4.25.8
        '4.25.0', '4.25.1', '4.25.2', '4.25.3', '4.25.4', '4.25.5',
        '4.25.6', '4.25.7',
        # 4.26.x versions before 4.26.6
        '4.26.0', '4.26.1', '4.26.2', '4.26.3', '4.26.4', '4.26.5',
        # 4.27.x versions before 4.27.2
        '4.27.0', '4.27.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if TerminAttr is enabled
    terminattr_config = str(commands.show_terminattr)
    terminattr_enabled = bool(terminattr_config)

    # Check if IPsec is configured
    ipsec_config = str(commands.show_ipsec)
    ipsec_configured = bool(ipsec_config)

    # Device is vulnerable if both TerminAttr and IPsec are enabled
    is_vulnerable = terminattr_enabled and ipsec_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28508. "
        "The device is running a vulnerable version AND has both TerminAttr and IPsec enabled, "
        "which could allow IPsec sensitive data to leak in clear text to CVP. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.27.2 or later for 4.27.x train\n"
        "  * 4.26.6 or later for 4.26.x train\n"
        "  * 4.25.8 or later for 4.25.x train\n"
        "  * 4.24.10 or later for 4.24.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Disable TerminAttr agent\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/15484-security-advisory-0077"
    )
