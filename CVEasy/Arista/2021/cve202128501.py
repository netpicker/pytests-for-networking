from comfy import high


@high(
    name='rule_cve202128501',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_terminattr='show running-config | include terminattr',
        show_openconfig='show running-config | include openconfig',
        show_users='show running-config | section username'
    ),
)
def rule_cve202128501(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28501 vulnerability in Arista EOS devices.
    The vulnerability allows unrestricted access to the device for local users with nopassword
    configuration due to incorrect use of EOS's AAA APIs by OpenConfig and TerminAttr agents.
    """
    # Extract the version information from the command output
    version_output = str(commands.show_version)

    # List of vulnerable software versions
    vulnerable_versions = [
        # TerminAttr versions before 1.16.2
        '1.15.0', '1.15.1', '1.15.2', '1.15.3',
        '1.16.0', '1.16.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if TerminAttr or OpenConfig agents are enabled
    terminattr_config = str(commands.show_terminattr)
    openconfig_config = str(commands.show_openconfig)
    agents_enabled = bool(terminattr_config or openconfig_config)

    # Check if any users are configured with nopassword
    users_config = str(commands.show_users)
    has_nopassword_users = 'nopassword' in users_config

    # Device is vulnerable if agents are enabled and has nopassword users
    is_vulnerable = agents_enabled and has_nopassword_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28501. "
        "The device is running a vulnerable version of TerminAttr AND has local users with nopassword configuration "
        "while OpenConfig/TerminAttr agents are enabled, which could allow unrestricted access. "
        "Recommended fixes:\n"
        "1. Upgrade to TerminAttr v1.16.2 or later\n"
        "2. Until upgrade is complete, implement these workarounds:\n"
        "  * Disable OpenConfig gNMI/gNOI and OpenConfig RESTCONF and TerminAttr\n"
        "  * Or apply the appropriate hotfix with proxy service:\n"
        "    - For 32-bit systems: SecurityAdvisory0071Hotfix.i386.swix\n"
        "    - For 64-bit systems: SecurityAdvisory0071Hotfix.x86_64.swix\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/13449-security-advisory-0071"
    )
