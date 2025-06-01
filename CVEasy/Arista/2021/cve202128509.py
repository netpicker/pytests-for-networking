from comfy import high


@high(
    name='rule_cve202128509',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_terminattr='show running-config | include terminattr',
        show_macsec='show running-config | section macsec'
    ),
)
def rule_cve202128509(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28509 vulnerability in Arista EOS devices.
    The vulnerability allows TerminAttr to leak MACsec sensitive data in clear text to CVP,
    which could allow authorized users to decrypt or modify MACsec traffic.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.23.x versions before 4.23.12
        '4.23.0', '4.23.1', '4.23.2', '4.23.3', '4.23.4', '4.23.5',
        '4.23.6', '4.23.7', '4.23.8', '4.23.9', '4.23.10', '4.23.11',
        # 4.24.x versions before 4.24.10
        '4.24.0', '4.24.1', '4.24.2', '4.24.3', '4.24.4', '4.24.5',
        '4.24.6', '4.24.7', '4.24.8', '4.24.9',
        # 4.25.x versions before 4.25.8
        '4.25.0', '4.25.1', '4.25.2', '4.25.3', '4.25.4', '4.25.5',
        '4.25.6', '4.25.7',
        # 4.26.x versions before 4.26.6
        '4.26.0', '4.26.1', '4.26.2', '4.26.3', '4.26.4', '4.26.5',
        # 4.27.x versions before 4.27.4
        '4.27.0', '4.27.1', '4.27.2', '4.27.3'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if TerminAttr is enabled
    terminattr_config = commands.show_terminattr
    terminattr_enabled = 'terminattr' in terminattr_config.lower()

    # Check if MACsec is configured
    macsec_config = commands.show_macsec
    macsec_configured = 'macsec' in macsec_config.lower()

    # Device is vulnerable if both TerminAttr and MACsec are enabled
    is_vulnerable = terminattr_enabled and macsec_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28509. "
        "The device is running a vulnerable version AND has both TerminAttr and MACsec enabled, "
        "which could allow MACsec sensitive data to leak in clear text to CVP. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.27.4 or later for 4.27.x train\n"
        "  * 4.26.6 or later for 4.26.x train\n"
        "  * 4.25.8 or later for 4.25.x train\n"
        "  * 4.24.10 or later for 4.24.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Disable TerminAttr agent\n"
        "For more information, see https://www.arista.com/en/support/advisories-notices/security-advisory/15484-security-advisory-0077"
    )
