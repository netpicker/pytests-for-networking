from comfy import high


@high(
    name='rule_cve20211390',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_diag='show running-config | include diagnostic|privilege exec level 15'
    ),
)
def rule_cve20211390(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1390 vulnerability in Cisco IOS XE Software.
    The vulnerability in diagnostic test CLI commands could allow an authenticated, local
    attacker with privilege level 15 to execute arbitrary code on the underlying Linux
    operating system due to insufficient run-time memory modification restrictions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for diagnostic test configuration and privileged users
    diag_config = commands.check_diag

    # Check if diagnostic tests are enabled
    diag_enabled = 'diagnostic' in diag_config

    # Check for users with privilege level 15 access
    has_privileged_users = 'privilege exec level 15' in diag_config

    # Device is vulnerable if diagnostic tests are enabled with privileged users
    is_vulnerable = diag_enabled and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1390. "
        "The device has diagnostic test commands enabled and users with privilege level 15, "
        "which could allow an authenticated local attacker to execute arbitrary code on the underlying OS. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-OFP-6Nezgn7b"
    )
