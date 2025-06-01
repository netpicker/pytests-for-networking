from comfy import high

@high(
    name='rule_cve202220810',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_snmp='show running-config | include snmp-server|wireless'
    ),
)
def rule_cve202220810(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20810 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient restrictions in the SNMP feature of Catalyst 9000 Family
    Wireless Controllers that could allow sensitive configuration details to be disclosed. An authenticated,
    remote attacker could exploit this vulnerability by retrieving data through SNMP read-only community access,
    allowing them to view SSID preshared keys (PSKs) configured on the device.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9000 Series
    is_cat9k = 'C9' in platform_output

    # If not a Catalyst 9000 device, it's not vulnerable
    if not is_cat9k:
        return

    # Extract the output of the command to check SNMP and wireless configuration
    snmp_output = commands.check_snmp

    # Check if SNMP and wireless are configured
    snmp_configured = 'snmp-server' in snmp_output
    wireless_configured = 'wireless' in snmp_output

    # Device is vulnerable if it's a Cat9K and has both SNMP and wireless configured
    is_vulnerable = is_cat9k and snmp_configured and wireless_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20810. "
        "The device is a Catalyst 9000 Series wireless controller with SNMP configured, "
        "which could allow an authenticated attacker to view SSID preshared keys through SNMP read-only access. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cwlc-snmpidv-rnyyQzUZ"
    )
