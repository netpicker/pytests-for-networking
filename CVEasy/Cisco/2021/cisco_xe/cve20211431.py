from comfy import high


@high(
    name='rule_cve20211431',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|vdaemon'
    ),
)
def rule_cve20211431(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1431 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in the vDaemon process could allow an unauthenticated, remote attacker
    to cause a device to reload, resulting in a denial of service (DoS) condition due to
    insufficient handling of malformed packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN configuration
    sdwan_config = commands.check_sdwan
    sdwan_enabled = 'sdwan' in sdwan_config

    # If SD-WAN is enabled, device is potentially vulnerable
    assert not sdwan_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1431. "
        "The device is running IOS XE SD-WAN Software with SD-WAN features enabled, "
        "which could allow an unauthenticated remote attacker to cause a denial of service condition "
        "through malformed packets sent to the vDaemon process. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-sdwdos-4zeEeC9w"
    )
