from comfy import high


@high(
    name='rule_cve20211625',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_zbfw='show running-config | include zone-pair|utd|appqoe'
    ),
)
def rule_cve20211625(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1625 vulnerability in Cisco IOS XE Software.
    The vulnerability in the Zone-Based Policy Firewall feature could allow an unauthenticated,
    remote attacker to prevent correct traffic classification when UTD or AppQoE is configured,
    potentially leading to traffic being dropped or incorrect HSL reporting.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for Zone-Based Firewall configuration with UTD or AppQoE
    zbfw_config = commands.check_zbfw

    # Check if Zone-Based Firewall is enabled
    zbfw_enabled = 'zone-pair' in zbfw_config

    # Check if UTD or AppQoE is enabled
    utd_appqoe_enabled = any(feature in zbfw_config for feature in [
        'utd',
        'appqoe'
    ])

    # Device is vulnerable if ZBFW is enabled with UTD or AppQoE
    is_vulnerable = zbfw_enabled and utd_appqoe_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1625. "
        "The device has Zone-Based Policy Firewall enabled with UTD or AppQoE configured, "
        "which could allow an unauthenticated remote attacker to cause incorrect traffic classification "
        "through ICMP or UDP flows. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-zbfw-pP9jfzwL"
    )
