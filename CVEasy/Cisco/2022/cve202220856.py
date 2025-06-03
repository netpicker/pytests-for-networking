from comfy import high


@high(
    name='rule_cve202220856',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_wireless='show running-config | include wireless|mobility'
    ),
)
def rule_cve202220856(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20856 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to a logic error and improper management of resources related to
    the handling of CAPWAP Mobility messages in Catalyst 9000 Family Wireless Controllers.
    An unauthenticated, remote attacker could exploit this vulnerability by sending crafted
    CAPWAP Mobility packets to exhaust resources on the affected device, causing it to reload.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9000 Series
    is_cat9k = 'C9' in platform_output

    # If not a Catalyst 9000 device, it's not vulnerable
    if not is_cat9k:
        return

    # Extract the output of the command to check wireless and mobility configuration
    wireless_output = commands.check_wireless

    # Check if wireless controller and mobility are configured
    wireless_configured = 'wireless' in wireless_output
    mobility_configured = 'mobility' in wireless_output

    # Device is vulnerable if it's a Cat9K and has both wireless and mobility configured
    is_vulnerable = is_cat9k and wireless_configured and mobility_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20856. "
        "The device is a Catalyst 9000 Series wireless controller with mobility configured, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted "
        "CAPWAP Mobility packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-mob-dos-342YAc6J"
    )
