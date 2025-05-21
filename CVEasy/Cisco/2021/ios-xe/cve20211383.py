from comfy import high


@high(
    name='rule_cve20211383',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|username'
    ),
)
def rule_cve20211383(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1383 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability allows an authenticated, local attacker with administrative privileges
    to access the underlying operating system with root privileges due to insufficient input
    validation of certain CLI commands.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN configuration and privileged users
    config = commands.check_sdwan

    # Check if SD-WAN is enabled
    sdwan_enabled = 'sdwan' in config

    # Check for administrative users
    has_admin_users = 'privilege 15' in config

    # Device is vulnerable if running SD-WAN with administrative users
    is_vulnerable = sdwan_enabled and has_admin_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1383. "
        "The device is running IOS XE SD-WAN Software with administrative users configured, "
        "which could allow an authenticated local attacker to access the underlying operating system "
        "with root privileges through parameter injection. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xesdwpinj-V4weeqzU"
    )
