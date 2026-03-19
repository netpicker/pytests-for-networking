from comfy import high

@high(
    name='rule_cve202520115',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config router bgp'
    ),
)
def rule_cve202520115(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20115 vulnerability in Cisco IOS XR Software.
    The vulnerability affects BGP confederation implementation and could allow an unauthenticated,
    remote attacker to cause a denial of service (DoS) condition through memory corruption when
    a BGP update is created with an AS_CONFED_SEQUENCE attribute that has 255 autonomous system numbers.
    """

    # Extract the output of the commands
    show_version_output = commands.show_version or ''
    show_running_config_output = commands.show_running_config or ''

    # Define the vulnerable software versions
    # According to the advisory: 7.11 and earlier, 24.1 and earlier, 24.2 (fixed in 24.2.21), 24.3 (fixed in 24.3.1)
    # 24.4 and later are not affected
    vulnerable_version_patterns = [
        '7.0.', '7.1.', '7.2.', '7.3.', '7.4.', '7.5.', '7.6.', '7.7.', '7.8.', '7.9.', '7.10.', '7.11.',
        '24.1.', '24.2.', '24.3.0'
    ]

    # Check if the device's software version is vulnerable
    is_vulnerable_version = any(pattern in show_version_output for pattern in vulnerable_version_patterns)

    # Check if BGP confederation is configured
    has_bgp_confederation = 'bgp confederation peers' in show_running_config_output

    # Device is vulnerable if it runs a vulnerable version AND has BGP confederation configured
    is_vulnerable = is_vulnerable_version and has_bgp_confederation

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20115. "
        f"The device is running a vulnerable version of Cisco IOS XR Software with BGP confederation configured. "
        f"This vulnerability could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition "
        f"through memory corruption when a BGP update with an AS_CONFED_SEQUENCE attribute has 255 or more AS numbers. "
        f"Please upgrade to a fixed release (24.3.1 or later, or 24.2.21 when available) or apply the workaround "
        f"to restrict AS_CONFED_SEQUENCE to 254 or fewer AS numbers using routing policy. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bgp-dos-O7stePhX"
    )