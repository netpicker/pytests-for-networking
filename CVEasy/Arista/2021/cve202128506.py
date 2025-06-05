from comfy import high


@high(
    name='rule_cve202128506',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_gnmi='show management api gnmi',
        show_restconf='show management api restconf',
        show_gnoi='show management api gnoi'
    ),
)
def rule_cve202128506(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28506 vulnerability in Arista EOS devices.
    The vulnerability allows unauthenticated attackers to bypass authentication in gNOI APIs,
    potentially allowing factory reset of the device.
    """
    # Extract the version information from the command output
    version_output = str(commands.show_version)

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.24.x versions before 4.24.8M
        '4.24.0', '4.24.1F', '4.24.2F', '4.24.3M', '4.24.4M', '4.24.5M', '4.24.6M', '4.24.7M',
        # 4.25.x versions before 4.25.6M
        '4.25.0', '4.25.1M', '4.25.2M', '4.25.3M', '4.25.4M', '4.25.5M',
        # 4.26.x versions before 4.26.3M
        '4.26.0', '4.26.1F', '4.26.2F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if any of the vulnerable APIs are enabled
    gnmi_config = str(commands.show_gnmi)
    restconf_config = str(commands.show_restconf)
    gnoi_config = str(commands.show_gnoi)

    apis_enabled = any([
        'enabled' in gnmi_config.lower(),
        'enabled' in restconf_config.lower(),
        'enabled' in gnoi_config.lower()
    ])

    # Device is vulnerable if running affected version and has APIs enabled
    is_vulnerable = version_vulnerable and apis_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28506. "
        "The device is running a vulnerable version AND has gNMI/gNOI/RESTCONF APIs enabled, "
        "which could allow unauthenticated attackers to bypass authentication and factory reset the device. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.26.3M or later for 4.26.x train\n"
        "  * 4.25.6M or later for 4.25.x train\n"
        "  * 4.24.8M or later for 4.24.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Apply the appropriate hotfix with proxy service:\n"
        "    - For 32-bit systems: SecurityAdvisory0071Hotfix.i386.swix\n"
        "    - For 64-bit systems: SecurityAdvisory0071Hotfix.x86_64.swix\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/13449-security-advisory-0071"
    )
