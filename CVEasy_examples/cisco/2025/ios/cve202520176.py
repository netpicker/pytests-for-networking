import re
from comfy import high


@high(
    name='rule_cve202520176',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include snmp-server'
    ),
)
def rule_cve202520176(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20176 vulnerability in Cisco IOS Software.
    The vulnerability is in the SNMP subsystem and is due to improper error handling when parsing
    SNMP requests. An authenticated, remote attacker could exploit this vulnerability by sending
    a crafted SNMP request to cause the device to reload unexpectedly, resulting in a DoS condition.
    This vulnerability affects SNMP versions 1, 2c, and 3.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Vulnerable version patterns with their fixed release numbers
    # (pattern, fixed_release_number)
    vulnerable_versions = [
        (r'15\.2\(7\)E(\d+)?', 12),   # Fixed in 15.2(7)E12
        (r'15\.5\(1\)SY(\d+)?', 15),  # Fixed in 15.5(1)SY15
        (r'15\.9\(3\)M(\d+)?', 11),   # Fixed in 15.9(3)M11
    ]

    # Check if the current device's software version is vulnerable
    version_vulnerable = False
    for pattern, fixed_num in vulnerable_versions:
        match = re.search(pattern, version_output)
        if match:
            release_num = match.group(1)
            # If no release number (e.g., "15.2(7)E") or release number < fixed, it's vulnerable
            if release_num is None or int(release_num) < fixed_num:
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
        f"Device {device.name} is vulnerable to CVE-2025-20176. "
        "The device is running a vulnerable version AND has SNMP enabled, "
        "which makes it susceptible to DoS attacks via crafted SNMP requests. "
        "An authenticated attacker could cause the device to reload unexpectedly. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-sdxnSUcW"
    )