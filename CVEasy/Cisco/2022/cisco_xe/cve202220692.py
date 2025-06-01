from comfy import high


@high(
    name='rule_cve202220692',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_netconf='show running-config | include netconf-yang|ssh'
    ),
)
def rule_cve202220692(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20692 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient resource management in the NETCONF over SSH feature.
    A low-privileged, authenticated, remote attacker could exploit this vulnerability by initiating
    a large number of NETCONF over SSH connections, causing the device to reload and resulting in
    a denial of service (DoS) condition.
    """
    # Extract the output of the command to check NETCONF configuration
    netconf_output = commands.check_netconf

    # Check if NETCONF over SSH is enabled
    netconf_enabled = 'netconf-yang' in netconf_output and 'ssh' in netconf_output

    # Assert that the device is not vulnerable
    assert not netconf_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20692. "
        "The device has NETCONF over SSH enabled, "
        "which could allow an authenticated attacker to cause a denial of service through multiple connections. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncossh-dos-ZAkfOdq8"
    )
