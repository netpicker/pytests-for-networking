from comfy import high


@high(
    name='rule_cve20211619',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_netconf='show running-config | include netconf|restconf|aaa|username.*privilege 15'
    ),
)
def rule_cve20211619(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1619 vulnerability in Cisco IOS XE Software.
    The vulnerability in the AAA function could allow an unauthenticated, remote attacker to
    bypass NETCONF or RESTCONF authentication and manipulate device configuration or cause a
    denial of service (DoS) condition due to an uninitialized variable.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for NETCONF/RESTCONF and AAA configuration
    config = commands.check_netconf

    # Check if NETCONF or RESTCONF is enabled
    api_enabled = any(feature in config for feature in [
        'netconf',
        'restconf'
    ])

    # Check if AAA is configured
    aaa_configured = 'aaa' in config

    # Device is vulnerable if NETCONF/RESTCONF is enabled with AAA
    is_vulnerable = api_enabled and aaa_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1619. "
        "The device has NETCONF/RESTCONF enabled with AAA configured, which could allow an "
        "unauthenticated remote attacker to bypass authentication and manipulate configuration "
        "or cause a denial of service condition. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aaa-Yx47ZT8Q"
    )
