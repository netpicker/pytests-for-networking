from comfy import high


@high(
    name='rule_cve20211485',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version'
    ),
)
def rule_cve20211485(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1485 vulnerability in Cisco IOS XR 64-Bit Software.
    The vulnerability allows an authenticated, local attacker to inject arbitrary commands
    that are executed with root privileges on the underlying Linux operating system of an
    affected device.
    """
    # Extract version information
    version_output = commands.show_version

    # List of fixed software versions
    fixed_versions = [
        '7.3.1'
    ]

    if any(version in version_output for version in fixed_versions):
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2021-1485. "
        "The device is running a vulnerable version. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-cmdinj-vsKGherc"
    )
