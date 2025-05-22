from comfy import high


@high(
    name='rule_cve202134728',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version'
    ),
)
def rule_cve202134728(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34728 vulnerability in Cisco IOS XR Software.
    The vulnerability allows an authenticated, local attacker with a low-privileged account
    to elevate privileges on an affected device due to insufficient input validation of
    commands supplied by the user.
    """
    # Extract version information
    version_output = commands.show_version

    # List of fixed software versions
    fixed_versions = [
        '7.3.2',
        '7.4.1'
    ]

    # Check if running fixed version
    if any(version in version_output for version in fixed_versions):
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2021-34728. "
        "The device is running a vulnerable version. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-privescal-dZYMrKf"
    )
