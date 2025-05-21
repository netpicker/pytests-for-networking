from comfy import high


@high(
    name='rule_cve20211128',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version'
    ),
)
def rule_cve20211128(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1128 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to insufficient application of restrictions during the execution
    of a specific command in the CLI parser. An authenticated, local attacker with low privileges
    could exploit this vulnerability by using a specific command at the command line, allowing
    them to view sensitive configuration information beyond their privilege level.

    Mitigation: Configure 'aaa authorization exec default local' to limit information displayed to unprivileged users.
    """
    # Extract version information
    version_output = commands.show_version

    # List of fixed software versions
    fixed_versions = [
        '6.7.2',
        '7.1.2',
        '7.2.1'
    ]

    if any(version in version_output for version in fixed_versions):
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2021-1128. "
        "The device is running a vulnerable version. Configure 'aaa authorization exec default local' "
        "to limit information displayed to unprivileged users. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-infodisc-4mtm9Gyt"
        )
