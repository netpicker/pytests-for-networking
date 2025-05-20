from comfy import high


@high(
    name='rule_cve20211352',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_decnet='show running-config | include decnet'
    ),
)
def rule_cve20211352(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1352 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation of DECnet traffic that could
    allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    _ = version_output
    # Check if DECnet is configured
    decnet_config = commands.check_decnet
    decnet_enabled = any(feature in decnet_config for feature in ['decnet', 'decnet-osi'])

    # If DECnet is enabled, device is potentially vulnerable
    assert not decnet_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1352. "
        "The device has DECnet Phase IV/OSI protocol enabled, which could allow an "
        "unauthenticated, adjacent attacker to cause a denial of service condition. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-decnet-dos-cuPWDkyL"
    )
