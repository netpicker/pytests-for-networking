from comfy import high


@high(
    name='rule_cve202134727',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|vdaemon'
    ),
)
def rule_cve202134727(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34727 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in the vDaemon process could allow an unauthenticated, remote attacker
    to cause a buffer overflow on an affected device due to insufficient bounds checking
    when processing traffic.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN configuration
    config = commands.check_sdwan

    # Check if SD-WAN is enabled
    sdwan_enabled = 'sdwan' in config

    # Device is vulnerable if running SD-WAN
    is_vulnerable = sdwan_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34727. "
        "The device is running IOS XE SD-WAN Software with vDaemon process, which could allow "
        "an unauthenticated remote attacker to cause a buffer overflow and execute arbitrary "
        "commands with root privileges or cause a denial of service condition. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxesdwan-rbuffover-vE2OB6tp"
    )
