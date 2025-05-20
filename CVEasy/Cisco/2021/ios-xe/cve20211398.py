from comfy import high


@high(
    name='rule_cve20211398',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_boot='show running-config | include boot|secure boot',
        check_users='show running-config | include privilege 15|username.*privilege'
    ),
)
def rule_cve20211398(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1398 vulnerability in Cisco IOS XE Software.
    The vulnerability in the boot logic could allow an authenticated, local attacker with level 15
    privileges or an unauthenticated attacker with physical access to execute arbitrary code on
    the underlying Linux operating system due to incorrect validations of function arguments
    passed to the boot script.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for boot configuration and privileged users
    boot_config = commands.check_boot
    users_config = commands.check_users

    # Check if UEFI secure boot is disabled
    secure_boot_disabled = 'secure boot' not in boot_config

    # Check for users with privilege level 15
    has_privileged_users = 'privilege 15' in users_config

    # Device is vulnerable if secure boot is disabled and has privileged users
    is_vulnerable = secure_boot_disabled and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1398. "
        "The device has UEFI secure boot disabled and users with privilege level 15, "
        "which could allow an attacker to execute arbitrary code during the boot process. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-ACE-75K3bRWe"
    )
