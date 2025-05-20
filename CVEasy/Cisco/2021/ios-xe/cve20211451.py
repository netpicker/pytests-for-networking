from comfy import high


@high(
    name='rule_cve20211451',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_vss='show running-config | include virtual-switch|easy-virtual-switch'
    ),
)
def rule_cve20211451(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1451 vulnerability in Cisco IOS XE Software.
    The vulnerability in the Easy Virtual Switching System (VSS) feature could allow an
    unauthenticated, remote attacker to execute arbitrary code on the underlying Linux
    operating system due to incorrect boundary checks in Easy VSS protocol packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Catalyst 4500/4500-X Series)
    platform_output = commands.check_platform
    vulnerable_platforms = ['WS-C4500', 'WS-C4500X']
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check for VSS configuration
    vss_config = commands.check_vss

    # Check if VSS is enabled
    vss_enabled = any(feature in vss_config for feature in [
        'virtual-switch',
        'easy-virtual-switch'
    ])

    # Device is vulnerable if VSS is enabled on a vulnerable platform
    is_vulnerable = vss_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1451. "
        "The device is a Catalyst 4500/4500-X Series switch with Easy VSS enabled, "
        "which could allow an unauthenticated remote attacker to execute arbitrary code "
        "through crafted Easy VSS protocol packets on UDP port 5500. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-evss-code-exe-8cw5VSvw"
    )
