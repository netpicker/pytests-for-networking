from comfy import high


@high(
    name='rule_cve20211391',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_debugger='show running-config | include dragonite|debug'
    ),
)
def rule_cve20211391(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1391 vulnerability in Cisco IOS Software.
    The vulnerability is due to the presence of development testing and verification scripts
    in the dragonite debugger that remained on the device. An authenticated, local attacker
    could exploit this vulnerability by bypassing the consent token mechanism with the residual
    scripts on the affected device, allowing them to escalate from privilege level 15 to root privilege.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS
    is_ios = 'Cisco IOS Software' in version_output

    # If not IOS, device is not vulnerable
    if not is_ios:
        return

    # Extract debugger configuration
    debugger_config = commands.check_debugger

    # Check for presence of dragonite debugger or debug commands
    debugger_enabled = any(feature in debugger_config for feature in [
        'dragonite',
        'debug privilege'
    ])

    # Device is vulnerable if debugger features are enabled
    is_vulnerable = debugger_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1391. "
        "The device has dragonite debugger or debug privilege commands enabled, "
        "which could allow an authenticated attacker to escalate from privilege level 15 to root privilege. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-FSM-Yj8qJbJc"
    )
