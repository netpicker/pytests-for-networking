from comfy import high


@high(
    name='rule_cve20211622',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_cops='show running-config | include cops|packetcable'
    ),
)
def rule_cve20211622(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1622 vulnerability in Cisco IOS XE Software for cBR-8 routers.
    The vulnerability in the Common Open Policy Service (COPS) could allow an unauthenticated,
    remote attacker to cause resource exhaustion and a denial of service (DoS) condition due to
    a deadlock condition when processing COPS packets.
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

    # Check for COPS configuration
    cops_config = commands.check_cops

    # Check if COPS or PacketCable features are enabled
    cops_enabled = any(feature in cops_config for feature in [
        'cops server',
        'packetcable',
        'cops listener'
    ])

    # Device is vulnerable if COPS is enabled on a cBR-8
    is_vulnerable = cops_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1622. "
        "The device is a cBR-8 router with COPS enabled, which could allow an unauthenticated "
        "remote attacker to cause resource exhaustion and a denial of service condition through "
        "high-rate COPS packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cbr8-cops-Vc2ZsJSx"
    )
