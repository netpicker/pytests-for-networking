from comfy import high


@high(
    name='rule_cve20211432',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_sdwan='show running-config | include sdwan|username'
    ),
)
def rule_cve20211432(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1432 vulnerability in Cisco IOS XE SD-WAN Software.
    The vulnerability allows an authenticated, local attacker with low privileges to execute
    arbitrary commands on the underlying operating system as the root user due to insufficient
    validation of user-supplied input in the CLI.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE SD-WAN software
    if 'IOS XE SD-WAN Software' not in version_output:
        return

    # Check for SD-WAN configuration and low-privileged users
    config = commands.check_sdwan

    # Check if SD-WAN is enabled
    sdwan_enabled = 'sdwan' in config

    # Check for users with low privileges (privilege level 1)
    has_low_priv_users = 'privilege 1' in config

    # Device is vulnerable if running SD-WAN with low-privileged users
    is_vulnerable = sdwan_enabled and has_low_priv_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1432. "
        "The device is running IOS XE SD-WAN Software with low-privileged users configured, "
        "which could allow an authenticated local attacker to inject commands with root privileges. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3"
    )
