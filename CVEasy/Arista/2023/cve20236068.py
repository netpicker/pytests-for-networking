from comfy import high


@high(
    name='rule_cve20236068',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_multiaccess='show running-config | section multiaccess'
    ),
)
def rule_cve20236068(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-6068 vulnerability in Arista MOS devices with MultiAccess FPGA.
    The vulnerability can cause incorrect operation of configured ACLs on ports, resulting in some
    packets that should be denied being permitted.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # MultiAccess FPGA versions
        'multiaccess-1.7.1',
        'multiaccess-1.6'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if MultiAccess FPGA is configured with ACLs
    config_output = commands.show_multiaccess
    acl_configured = 'access-list' in config_output

    # Assert that the device is not vulnerable
    assert not acl_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-6068. "
        "The device is running a vulnerable version of MultiAccess FPGA software "
        "and has ACLs configured, which may result in incorrect ACL operation. "
        "Recommended fixes:\n"
        "- Upgrade to MultiAccess FPGA 1.8.0 or later\n"
        "Workaround:\n"
        "- Only apply one access-list to any particular port after the MultiAccess image is loaded\n"
        "- If a new access-list needs to be applied, reload the FPGA image after applying it\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/19023-security-advisory-0091"
    )
