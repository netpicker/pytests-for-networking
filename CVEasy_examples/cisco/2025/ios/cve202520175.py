from comfy import high


@high(
    name='rule_cve202520175',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_snmp_config='show running-config | include snmp-server'
    ),
)
def rule_cve202520175(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20175 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper error handling when parsing SNMP requests, which can be
    exploited by an authenticated, remote attacker to cause a denial of service (DoS) condition
    by reloading the device. This affects SNMP versions 1, 2c, and 3.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on the advisory
    vulnerable_versions = [
        # 15.2E versions (vulnerable until 15.2(7)E12)
        '15.2(1)E', '15.2(2)E', '15.2(3)E', '15.2(4)E', '15.2(5)E', '15.2(6)E', '15.2(7)E',
        # 15.5SY versions (vulnerable until 15.5(1)SY15)
        '15.5(1)SY',
        # 15.9M versions (vulnerable until 15.9(3)M11)
        '15.9(3)M',
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

    # If SNMP is enabled in any version, the device is vulnerable
    is_vulnerable = snmp_community_enabled or snmp_v3_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20175. "
        "The device is running a vulnerable version AND has SNMP enabled (v1, v2c, or v3), "
        "which makes it susceptible to DoS attacks via crafted SNMP requests. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
    )