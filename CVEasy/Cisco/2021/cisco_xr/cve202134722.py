from comfy import high


@high(
    name='rule_cve202134722',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_xml_agent='show running-config | include xml agent'
    ),
)
def rule_cve202134722(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34722 vulnerability in Cisco IOS XR Software.
    The vulnerability allows an authenticated, local attacker to gain access to the root shell
    of an affected device and execute arbitrary commands with root privileges due to insufficient
    input validation in the CLI.

    Affected versions: Cisco IOS XR Software releases 7.1.1 through 7.3.1
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

    # Check if xml agent is enabled
    xml_agent_output = commands.show_xml_agent
    xml_agent_enabled = 'xml agent' in xml_agent_output

    if not xml_agent_enabled:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2021-34722. "
        "The device is running a vulnerable version and has XML agent enabled. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-cmd-inj-wbZKvPxc"
    )
