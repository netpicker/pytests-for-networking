from comfy import high

@high(
    name='rule_cve202521599',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_ipv6='show configuration | display set | match "family inet6"'
    ),
)
def rule_cve202521599(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21599 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause Denial of Service
    through memory exhaustion by sending malformed IPv6 packets to devices with IPv6 configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Junos OS Evolved
    is_evolved = 'Junos OS Evolved' in version_output or '-EVO' in version_output

    # This issue only affects Junos OS Evolved
    if not is_evolved:
        return

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # 22.4-EVO before 22.4R3-S5-EVO
    vulnerable_versions.extend([
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO',
        '22.4R3-S1-EVO', '22.4R3-S2-EVO', '22.4R3-S3-EVO', '22.4R3-S4-EVO'
    ])
    
    # 23.2-EVO before 23.2R2-S2-EVO
    vulnerable_versions.extend([
        '23.2R1-EVO', '23.2R2-EVO', '23.2R2-S1-EVO'
    ])
    
    # 23.4-EVO before 23.4R2-S2-EVO
    vulnerable_versions.extend([
        '23.4R1-EVO', '23.4R2-EVO', '23.4R2-S1-EVO'
    ])
    
    # 24.2-EVO before 24.2R1-S2-EVO, 24.2R2-EVO
    vulnerable_versions.extend([
        '24.2R1-EVO', '24.2R1-S1-EVO'
    ])

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if IPv6 is configured
    ipv6_config_output = commands.show_config_ipv6
    has_ipv6_configured = 'family inet6' in ipv6_config_output

    # If IPv6 is not configured, the device is not vulnerable
    if not has_ipv6_configured:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-21599. "
        "The device is running a vulnerable version of Junos OS Evolved with IPv6 configured, "
        "which makes it susceptible to Denial of Service through memory exhaustion when receiving "
        "malformed IPv6 packets destined to the device. "
        "For more information, see https://supportportal.juniper.net/JSA88316"
    )