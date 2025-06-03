from comfy import high


@high(
    name='rule_cve20211452',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_rommon='show rom-monitor'
    ),
)
def rule_cve20211452(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1452 vulnerability in Cisco IOS XE ROMMON Software.
    The vulnerability in the ROM Monitor could allow an unauthenticated, physical attacker
    to execute unsigned code at system boot time due to incorrect validations of function
    arguments passed to a boot script when specific ROMMON variables are set.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Industrial or Embedded Series)
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'IE-3200',
        'IE-3300',
        'IE-3400',
        'ESR-3300'
    ]
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check ROMMON configuration
    rommon_output = commands.check_rommon

    # Check if ROMMON is in a vulnerable state (not upgraded to a fixed version)
    # Note: This is a basic check - specific ROMMON versions would need to be checked
    # against Cisco's advisory for complete verification
    rommon_vulnerable = 'ROMMON' in rommon_output

    # Device is vulnerable if it's a vulnerable platform with vulnerable ROMMON
    is_vulnerable = is_vulnerable_platform and rommon_vulnerable

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1452. "
        "The device is an Industrial or Embedded Series switch with potentially vulnerable ROMMON, "
        "which could allow an unauthenticated physical attacker to execute unsigned code at boot time. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-romvar-cmd-inj-N56fYbrw"
    )
