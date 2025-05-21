from comfy import high


@high(
    name='rule_cve202134719',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version'
    ),
)
def rule_cve202134719(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34719 vulnerability in Cisco IOS XR Software.
    The vulnerability allows an authenticated, local attacker with low privileges to
    elevate privileges to root on an affected device by submitting crafted input to
    a specific command.
    """
    # Extract version information
    version_output = commands.show_version

    # List of fixed software versions
    fixed_versions = [
        '7.3.2',
        '7.4.1'
    ]

    if any(version in version_output for version in fixed_versions):
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2021-34719. "
        "The device is running a vulnerable version. "
        ""For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-privescal-dZYMrKf""
    )
