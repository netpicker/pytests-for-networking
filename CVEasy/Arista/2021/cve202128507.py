from comfy import high


@high(
    name='rule_cve202128507',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_openconfig='show running-config | include openconfig',
        show_restconf='show management api restconf',
        show_acl='show running-config | section service-acl'
    ),
)
def rule_cve202128507(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28507 vulnerability in Arista EOS devices.
    The vulnerability allows service ACL bypass in OpenConfig gNOI and RESTCONF APIs,
    which could result in denied requests being forwarded to the agent.
    """
    # Extract the version information from the command output
    version_output = str(commands.show_version)

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.21.x and earlier versions
        '4.21.', '4.20.', '4.19.', '4.18.',
        # 4.22.x versions
        '4.22.0', '4.22.1', '4.22.2', '4.22.3',
        # 4.23.x versions before 4.23.10M
        '4.23.0', '4.23.1', '4.23.2', '4.23.3', '4.23.4',
        '4.23.5', '4.23.6', '4.23.7', '4.23.8', '4.23.9',
        # 4.24.x versions before 4.24.8M
        '4.24.0', '4.24.1', '4.24.2', '4.24.3', '4.24.4',
        '4.24.5', '4.24.6', '4.24.7',
        # 4.25.x versions before 4.25.6M
        '4.25.0', '4.25.1', '4.25.2', '4.25.3', '4.25.4', '4.25.5',
        # 4.26.x versions before 4.26.3M
        '4.26.0', '4.26.1', '4.26.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if OpenConfig or RESTCONF is enabled
    openconfig_config = str(commands.show_openconfig)
    restconf_config = str(commands.show_restconf)
    apis_enabled = bool(openconfig_config or 'enabled' in restconf_config.lower())

    # Check if service ACLs are configured
    acl_config = str(commands.show_acl)
    has_service_acl = 'service-acl' in acl_config

    # Device is vulnerable if APIs are enabled and using service ACLs
    is_vulnerable = apis_enabled and has_service_acl

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28507. "
        "The device is running a vulnerable version AND has OpenConfig/RESTCONF APIs enabled with service ACLs, "
        "which could allow denied requests to bypass ACLs and reach the agent. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.26.3M or later for 4.26.x train\n"
        "  * 4.25.6M or later for 4.25.x train\n"
        "  * 4.24.8M or later for 4.24.x train\n"
        "  * 4.23.10M or later for 4.23.x train\n"
        "2. Until upgrade is complete, implement these workarounds:\n"
        "  * Disable OpenConfig gNMI/gNOI and OpenConfig RESTCONF\n"
        "  * Or apply the appropriate hotfix with proxy service:\n"
        "    - For 32-bit systems: SecurityAdvisory0071Hotfix.i386.swix\n"
        "    - For 64-bit systems: SecurityAdvisory0071Hotfix.x86_64.swix\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/13449-security-advisory-0071"
    )
