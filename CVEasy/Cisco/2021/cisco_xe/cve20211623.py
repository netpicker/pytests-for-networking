from comfy import high


@high(
    name='rule_cve20211623',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_snmp='show running-config | include snmp-server'
    ),
)
def rule_cve20211623(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1623 vulnerability in Cisco IOS XE Software for cBR-8 routers.
    The vulnerability in the SNMP punt handling function could allow an authenticated, remote
    attacker to overload a device punt path, resulting in a denial of service (DoS) condition
    through a large number of SNMP requests.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a cBR-8 platform
    platform_output = commands.check_platform
    is_cbr8 = 'CBR-8' in platform_output

    if not is_cbr8:
        return

    # Check for SNMP configuration
    snmp_config = commands.check_snmp

    # Check if SNMP is enabled
    snmp_enabled = 'snmp-server' in snmp_config

    # Device is vulnerable if SNMP is enabled on a cBR-8
    is_vulnerable = snmp_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1623. "
        "The device is a cBR-8 router with SNMP enabled, which could allow an authenticated "
        "remote attacker to cause a denial of service condition through high-rate SNMP requests. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cbr8snmp-zGjkZ9Fc"
    )
