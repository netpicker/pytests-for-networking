from comfy import high


@high(
    name='rule_cve20211433',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|vmanage'
    ),
)
def rule_cve20211433(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1433 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability in the vDaemon process could allow an unauthenticated, remote attacker
    to cause a buffer overflow on an affected device through malformed packets when positioned
    between vManage and the device, potentially leading to arbitrary code execution or DoS.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN configuration and vManage connection
    config = commands.check_sdwan

    # Check if SD-WAN is enabled and connected to vManage
    sdwan_enabled = 'sdwan' in config
    vmanage_configured = 'vmanage' in config

    # Device is vulnerable if running SD-WAN and connected to vManage
    is_vulnerable = sdwan_enabled and vmanage_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1433. "
        "The device is running IOS XE SD-WAN Software and is connected to vManage, "
        "which could allow an unauthenticated remote attacker to cause a buffer overflow "
        "through malformed packets when positioned between vManage and the device. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-buffover-CqdRWLc"
    )
