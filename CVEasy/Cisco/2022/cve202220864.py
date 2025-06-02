from comfy import high


@high(
    name='rule_cve202220864',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_password_recovery='show running-config | include no service password-recovery'
    ),
)
def rule_cve202220864(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20864 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to a problem with the file and boot variable permissions in ROMMON
    when password recovery is disabled. An unauthenticated, local attacker could exploit this
    vulnerability by rebooting the switch into ROMMON and entering specific commands through
    the console to read any file or reset the enable password.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst switch
    is_catalyst = 'C9' in platform_output

    # If not a Catalyst switch, it's not vulnerable
    if not is_catalyst:
        return

    # Extract the output of the command to check password recovery configuration
    password_recovery_output = commands.check_password_recovery

    # Check if password recovery is disabled
    password_recovery_disabled = 'no service password-recovery' in password_recovery_output

    # Assert that the device is not vulnerable
    assert not password_recovery_disabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20864. "
        "The device is a Catalyst switch with password recovery disabled, "
        "which could allow an unauthenticated attacker with physical access to recover configuration "
        "or reset passwords. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-info-disc-nrORXjO"
    )
