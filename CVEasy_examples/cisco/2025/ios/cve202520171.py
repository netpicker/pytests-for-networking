from comfy import high


@high(
    name='rule_cve202520171',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_snmp_config='show running-config | include snmp-server'
    ),
)
def rule_cve202520171(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20171 vulnerability in Cisco IOS Software.
    The vulnerability is in the SNMP subsystem and is due to improper error handling when parsing
    SNMP requests. An authenticated, remote attacker could exploit this vulnerability by sending
    a crafted SNMP request to cause the device to reload unexpectedly, resulting in a DoS condition.
    This affects SNMP versions 1, 2c, and 3.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on the advisory
    # Versions before the fixed releases are vulnerable
    vulnerable_version_patterns = [
        '15.2(7)E',  # Before 15.2(7)E12
        '15.5(1)SY',  # Before 15.5(1)SY15
        '15.9(3)M',  # Before 15.9(3)M11
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = False
    for pattern in vulnerable_version_patterns:
        if pattern in version_output:
            # Extract version number to check if it's before the fixed version
            if '15.2(7)E' in version_output and '15.2(7)E12' not in version_output:
                version_vulnerable = True
                break
            elif '15.5(1)SY' in version_output and '15.5(1)SY15' not in version_output:
                version_vulnerable = True
                break
            elif '15.9(3)M' in version_output and '15.9(3)M11' not in version_output:
                version_vulnerable = True
                break

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check if SNMP is enabled
    snmp_config_output = commands.show_snmp_config

    # Check if SNMP v1/v2c is enabled (community strings configured)
    snmp_community_enabled = 'snmp-server community' in snmp_config_output

    # Check if SNMP v3 is enabled (groups or users configured)
    snmp_v3_enabled = 'snmp-server group' in snmp_config_output or 'snmp-server user' in snmp_config_output

    # If SNMP is enabled (any version), the device is vulnerable
    is_vulnerable = snmp_community_enabled or snmp_v3_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20171. "
        "The device is running a vulnerable version of Cisco IOS Software AND has SNMP enabled, "
        "which makes it susceptible to DoS attacks via crafted SNMP requests. "
        "An authenticated attacker could cause the device to reload unexpectedly. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
    )