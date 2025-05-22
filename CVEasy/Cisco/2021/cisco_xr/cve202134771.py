from comfy import high


@high(
    name='rule_cve202134771',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version'
    ),
)
def rule_cve202134771(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34771 vulnerability in Cisco IOS XR Software.
    The vulnerability allows an authenticated, local attacker to view more information
    than their privileges allow due to insufficient application of restrictions during
    command execution.
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
        f"Device {device.name} is vulnerable to CVE-2021-34771. "
        "The device is running a vulnerable version. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-infodisc-CjLdGMc5"
    )
