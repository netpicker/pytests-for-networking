from comfy import medium

@medium(
    name='rule_cve202520214',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_netconf='show running-config | include netconf-yang',
        show_restconf='show running-config | include restconf',
        show_gnmi='show running-config | include gnmi',
        show_nacm='show running-config | section nacm'
    ),
)
def rule_cve202520214(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20214 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the Network Configuration Access Control Module (NACM) could allow
    an authenticated, remote attacker to obtain unauthorized read access to configuration
    or operational data. This vulnerability exists because a subtle change in inner API
    call behavior causes results to be filtered incorrectly.
    
    The vulnerability requires:
    - Vulnerable IOS XE version
    - NETCONF, RESTCONF, or gNMI enabled
    - NACM configured with restricted read access for lower-privileged users
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 16.x versions
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6', '16.3.7', '16.3.8',
        '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6', '16.6.7', '16.6.8',
        '16.6.9', '16.6.10',
        '16.7.1', '16.7.2', '16.7.3',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.2', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1e', '16.10.2', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        '17.13.1', '17.13.1a',
        '17.14.1', '17.14.1a',
        '17.15.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if NETCONF, RESTCONF, or gNMI is enabled
    netconf_enabled = 'netconf-yang' in commands.show_netconf
    restconf_enabled = 'restconf' in commands.show_restconf
    gnmi_enabled = 'gnmi' in commands.show_gnmi

    # Check if NACM is configured
    nacm_configured = 'nacm' in commands.show_nacm and len(commands.show_nacm.strip()) > 0

    # Device is vulnerable if:
    # 1. Running vulnerable version
    # 2. Has NETCONF, RESTCONF, or gNMI enabled
    # 3. Has NACM configured with restricted read access
    if (netconf_enabled or restconf_enabled or gnmi_enabled) and nacm_configured:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20214. "
            "The device is running a vulnerable IOS XE version with NETCONF/RESTCONF/gNMI enabled "
            "and NACM configured for restricted read access. An authenticated attacker with low privileges "
            "could bypass NACM restrictions to access unauthorized configuration or operational data. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-netconf-nacm-bypass-TGZV9pmQ"
        )