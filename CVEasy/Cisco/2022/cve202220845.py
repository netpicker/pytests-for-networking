from comfy import high


@high(
    name='rule_cve202220845',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_tl1='show processes | include tl1'
    ),
)
def rule_cve202220845(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20845 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to TL1 not freeing memory under some conditions in NCS 4000 Series devices.
    An authenticated, local attacker could exploit this vulnerability by connecting to the device and
    issuing TL1 commands, causing the TL1 process to consume large amounts of memory and potentially
    leading to a denial of service condition.
    """
    # List of vulnerable versions
    vulnerable_versions = [
        '6.5.25', '6.5.26', '6.5.28', '6.5.29', '6.5.31', '6.5.32'
    ]

    # Extract the version information
    version_output = commands.show_version

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is an NCS 4000 Series
    is_ncs4k = 'NCS-4' in platform_output

    # If not an NCS 4000 device, it's not vulnerable
    if not is_ncs4k:
        return

    # Extract the output of the command to check TL1 process
    tl1_output = commands.check_tl1

    # Check if TL1 process is running
    tl1_running = 'tl1' in tl1_output

    # Assert that the device is not vulnerable
    assert not tl1_running, (
        f"Device {device.name} is vulnerable to CVE-2022-20845. "
        "The device is an NCS 4000 Series running a vulnerable version with TL1 process enabled, "
        "which could allow an authenticated attacker to cause a denial of service through memory exhaustion. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncs4k-tl1-GNnLwC6"
    )
