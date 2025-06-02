from comfy import high


@high(
    name='rule_cve202220683',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_fnf='show running-config | include flow|performance monitor'
    ),
)
def rule_cve202220683(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20683 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient packet verification for traffic inspected by the AVC feature
    in Cisco Catalyst 9800 Series Wireless Controllers. An unauthenticated, remote attacker could exploit
    this vulnerability by sending crafted packets from the wired network to a wireless client, causing
    the wireless controller to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9800 Series
    is_cat9800 = 'C9800' in platform_output

    # If not a Catalyst 9800 device, it's not vulnerable
    if not is_cat9800:
        return

    # Extract the output of the command to check AVC/FNF configuration
    fnf_output = commands.check_fnf

    # Check if AVC/FNF is configured
    fnf_configured = any(feature in fnf_output for feature in ['flow', 'performance monitor'])

    # Device is vulnerable if it's a Cat9800 and has AVC/FNF configured
    is_vulnerable = is_cat9800 and fnf_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20683. "
        "The device is a Catalyst 9800 Series wireless controller with AVC/FNF configured, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-fnf-dos-bOL5vLge"
    )
