from comfy import high


@high(
    name='rule_cve202520173',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_snmp_config='show running-config | include snmp-server'
    ),
)
def rule_cve202520173(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20173 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper error handling when parsing SNMP requests, which can be
    exploited by an authenticated, remote attacker to cause a denial of service (DoS) condition
    by reloading the device. This affects SNMP versions 1, 2c, and 3.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Fixed versions - at or above these are not vulnerable
    fixed_versions = [
        '15.2(7)E12', '15.2(7)E13', '15.2(7)E14',
        '15.5(1)SY15', '15.5(1)SY16', '15.5(1)SY17',
        '15.9(3)M11', '15.9(3)M12', '15.9(3)M13',
        '16.', '17.'  # Major releases 16.x and 17.x are fixed
    ]
    
    # Check if running a fixed version first
    is_fixed = any(fixed in version_output for fixed in fixed_versions)
    if is_fixed:
        return

    # List of vulnerable software versions based on the advisory
    vulnerable_versions = [
        # 15.2E versions (vulnerable until 15.2(7)E12)
        '15.2(1)E', '15.2(2)E', '15.2(3)E', '15.2(4)E', '15.2(5)E', '15.2(6)E', '15.2(7)E',
        # 15.5SY versions (vulnerable until 15.5(1)SY15)
        '15.5(1)SY', '15.5(1)SY1', '15.5(1)SY2', '15.5(1)SY3', '15.5(1)SY4', '15.5(1)SY5',
        '15.5(1)SY6', '15.5(1)SY7', '15.5(1)SY8', '15.5(1)SY9', '15.5(1)SY10', '15.5(1)SY11',
        '15.5(1)SY12', '15.5(1)SY13', '15.5(1)SY14',
        # 15.9M versions (vulnerable until 15.9(3)M11)
        '15.9(3)M', '15.9(3)M1', '15.9(3)M2', '15.9(3)M3', '15.9(3)M4', '15.9(3)M5',
        '15.9(3)M6', '15.9(3)M7', '15.9(3)M8', '15.9(3)M9', '15.9(3)M10'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check if SNMP is enabled
    snmp_config_output = commands.show_snmp_config

    # Check if SNMP v1/v2c is enabled (community strings configured)
    snmp_community_enabled = 'snmp-server community' in snmp_config_output

    # Check if SNMP v3 is enabled (group or user configured)
    snmp_v3_enabled = 'snmp-server group' in snmp_config_output or 'snmp-server user' in snmp_config_output

    # If SNMP is enabled (any version), the device is vulnerable
    is_vulnerable = snmp_community_enabled or snmp_v3_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20173. "
        "The device is running a vulnerable version AND has SNMP enabled (v1, v2c, or v3), "
        "which makes it susceptible to DoS attacks via crafted SNMP requests. "
        "An authenticated attacker can cause the device to reload unexpectedly. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
    )