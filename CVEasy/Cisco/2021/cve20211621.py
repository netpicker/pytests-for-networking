from comfy import high


@high(
    name='rule_cve20211621',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_l2='show running-config | include switchport|spanning-tree|vlan'
    ),
)
def rule_cve20211621(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1621 vulnerability in Cisco IOS XE Software.
    The vulnerability in the Layer 2 punt code could allow an unauthenticated, adjacent
    attacker to cause a queue wedge on an interface that receives specific Layer 2 frames,
    resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for Layer 2 switching configuration
    l2_config = commands.check_l2

    # Check if Layer 2 switching features are enabled
    l2_enabled = any(feature in l2_config for feature in [
        'switchport',
        'spanning-tree',
        'vlan'
    ])

    # Device is vulnerable if Layer 2 switching is enabled
    is_vulnerable = l2_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1621. "
        "The device has Layer 2 switching features enabled, which could allow an unauthenticated "
        "adjacent attacker to cause a queue wedge on an interface through malformed Layer 2 frames. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-quewedge-69BsHUBW"
    )
