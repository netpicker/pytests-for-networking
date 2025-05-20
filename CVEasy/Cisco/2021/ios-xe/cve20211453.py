from comfy import high


@high(
    name='rule_cve20211453',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_boot='show running-config | include secure boot|boot system'
    ),
)
def rule_cve20211453(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1453 vulnerability in Cisco IOS XE Software for Catalyst 9000 Family.
    The vulnerability in the software image verification functionality could allow an unauthenticated,
    physical attacker to execute unsigned code at system boot time due to improper checks in the code
    function that manages digital signature verification during boot.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Catalyst 9000 Family)
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9200', 'C9300', 'C9400',
        'C9500', 'C9600', 'C9800'
    ]
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check boot configuration
    boot_config = commands.check_boot

    # Check if secure boot is disabled
    secure_boot_disabled = 'secure boot' not in boot_config

    # Device is vulnerable if secure boot is disabled on a Cat9k
    is_vulnerable = secure_boot_disabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1453. "
        "The device is a Catalyst 9000 Series switch with secure boot disabled, "
        "which could allow an unauthenticated physical attacker to execute unsigned code at boot time. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cat-verify-BQ5hrXgH"
    )
