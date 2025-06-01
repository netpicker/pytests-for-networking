from comfy import high


@high(
    name='rule_cve202128500',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_users='show running-config | section username',
        show_agents='show running-config | include openconfig|terminattr'
    ),
)
def rule_cve202128500(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28500 vulnerability in Arista EOS devices.
    The vulnerability allows unrestricted access to the device for local users with nopassword
    configuration due to incorrect use of EOS's AAA APIs by OpenConfig and TerminAttr agents.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.20.x and earlier versions
        '4.20.0', '4.20.15',
        # 4.21.x versions
        '4.21.0', '4.21.14M',
        # 4.22.x versions
        '4.22.0', '4.22.11M',
        # 4.23.x versions
        '4.23.0', '4.23.8M',
        # 4.24.x versions
        '4.24.0', '4.24.6M',
        # 4.25.x versions
        '4.25.0', '4.25.4M',
        # 4.26.x versions
        '4.26.0', '4.26.1F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if any users are configured with nopassword
    users_config = commands.show_users
    has_nopassword_users = 'nopassword' in users_config

    # Check if OpenConfig or TerminAttr agents are enabled
    agents_config = commands.show_agents
    agents_enabled = 'openconfig' in agents_config or 'terminattr' in agents_config

    # Device is vulnerable if it has nopassword users and agents enabled
    is_vulnerable = has_nopassword_users and agents_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28500. "
        "The device is running a vulnerable version AND has local users with nopassword configuration "
        "while OpenConfig/TerminAttr agents are enabled, which could allow unrestricted access. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.26.2F or later for 4.26.x train\n"
        "  * 4.25.5M or later for 4.25.x train\n"
        "  * 4.24.7M or later for 4.24.x train\n"
        "  * 4.23.9M or later for 4.23.x train\n"
        "  * 4.22.12M or later for 4.22.x train\n"
        "  * 4.21.15M or later for 4.21.x train\n"
        "2. Until upgrade is complete, implement these workarounds:\n"
        "  * Remove nopassword configuration for local users\n"
        "  * Or apply the appropriate hotfix:\n"
        "    - For 32-bit systems: SecurityAdvisory0071Hotfix.i386.swix\n"
        "    - For 64-bit systems: SecurityAdvisory0071Hotfix.x86_64.swix\n"
        "For more information, see "
        "https://www.arista.com/en/support/advisories-notices/security-advisory/13449-security-advisory-0071"
    )
