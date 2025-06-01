from comfy import high


@high(
    name='rule_cve202220678',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_appnav='show running-config | include appnav-controller|service-insertion'
    ),
)
def rule_cve202220678(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20678 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to incorrect handling of certain TCP segments in the AppNav-XE feature.
    An unauthenticated, remote attacker could exploit this vulnerability by sending a stream of crafted
    TCP traffic at a high rate through an interface with AppNav interception enabled, causing the device
    to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check AppNav configuration
    appnav_output = commands.check_appnav

    # Check if AppNav-XE is configured
    appnav_configured = any(feature in appnav_output for feature in [
        'appnav-controller', 'service-insertion'
    ])

    # Assert that the device is not vulnerable
    assert not appnav_configured, (
        f"Device {device.name} is vulnerable to CVE-2022-20678. "
        "The device has AppNav-XE configured, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted TCP traffic. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-appnav-xe-dos-j5MXTR4"
    )
