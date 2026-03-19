from comfy import high


@high(
    name='rule_cve202520169',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include snmp-server'
    ),
)
def rule_cve202520169(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20169 vulnerability in Cisco IOS Software.
    The vulnerability is in the SNMP subsystem and is due to improper error handling when parsing
    SNMP requests. An authenticated, remote attacker could exploit this vulnerability by sending
    a crafted SNMP request to cause the device to reload unexpectedly, resulting in a DoS condition.
    This vulnerability affects SNMP versions 1, 2c, and 3.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Fixed versions - at or above these are not vulnerable
    fixed_versions = [
        '15.2(7)E12', '15.2(7)E13', '15.2(7)E14', '15.2(7)E15',
        '15.5(1)SY15', '15.5(1)SY16', '15.5(1)SY17',
        '15.9(3)M11', '15.9(3)M12', '15.9(3)M13',
        '16.', '17.'  # Major releases 16.x and 17.x are fixed
    ]
    
    # Check if running a fixed version
    is_fixed = any(fixed in version_output for fixed in fixed_versions)
    if is_fixed:
        return

    # List of vulnerable software versions based on the advisory
    vulnerable_version_patterns = [
        '15.2(7)E',  # Before 15.2(7)E12
        '15.5(1)SY',  # Before 15.5(1)SY15
        '15.9(3)M',  # Before 15.9(3)M11
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = False
    for pattern in vulnerable_version_patterns:
        if pattern in version_output:
            version_vulnerable = True
            break

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check if SNMP is enabled
    config_output = commands.show_running_config

    # Check if SNMP v1/v2c is enabled (community strings configured)
    snmp_community_enabled = 'snmp-server community' in config_output

    # Check if SNMP v3 is enabled (group or user configured)
    snmp_v3_enabled = 'snmp-server group' in config_output or 'snmp-server user' in config_output

    # If SNMP is enabled in any version, the device is vulnerable
    is_vulnerable = snmp_community_enabled or snmp_v3_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20169. "
        "The device is running a vulnerable version AND has SNMP enabled (v1, v2c, or v3), "
        "which makes it susceptible to DoS attacks via crafted SNMP requests. "
        "An authenticated attacker could cause the device to reload unexpectedly. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
    )