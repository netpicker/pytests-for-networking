from comfy import high


@high(
    name='rule_cve20211281',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|confd'
    ),
)
def rule_cve20211281(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1281 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability allows an authenticated, local attacker to access the underlying
    operating system as the root user due to improper handling of concurrent CLI sessions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN/confd configuration
    sdwan_config = commands.check_sdwan
    sdwan_enabled = any(feature in sdwan_config for feature in ['sdwan', 'confd'])

    # If SD-WAN is enabled, device is potentially vulnerable
    assert not sdwan_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1281. "
        "The device is running IOS XE SD-WAN Software and has SD-WAN features enabled, "
        "which could allow an authenticated local attacker to gain root access. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-clipriv-9TO2QGVp"
    )
