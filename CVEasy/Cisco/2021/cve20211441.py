from comfy import high


@high(
    name='rule_cve20211441',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_users='show running-config | include username.*privilege 15'
    ),
)
def rule_cve20211441(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1441 vulnerability in Cisco IOS XE Software for 1100 Series
    Industrial ISRs and ESR6300 Embedded Series Routers. The vulnerability in hardware initialization
    routines could allow an authenticated, local attacker with level 15 privileges to execute
    unsigned code at system boot time.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (1100 Series Industrial ISR or ESR6300)
    platform_output = commands.check_platform
    vulnerable_platforms = ['IR1101', 'IR1111', 'IR1113', 'ESR6300']
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check for users with privilege level 15
    users_config = commands.check_users
    has_privileged_users = 'privilege 15' in users_config

    # Device is vulnerable if it's a vulnerable platform with privileged users
    is_vulnerable = is_vulnerable_platform and has_privileged_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1441. "
        "The device is a 1100 Series Industrial ISR or ESR6300 router with privileged users configured, "
        "which could allow an authenticated local attacker to execute unsigned code at boot time. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-iot-codexec-k46EFF6q"
    )
