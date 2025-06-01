from comfy import high


@high(
    name='rule_cve202220655',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_confd='show processes confd'
    ),
)
def rule_cve202220655(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20655 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to insufficient validation of a process argument in the ConfD CLI.
    An authenticated, local attacker could exploit this vulnerability by injecting commands during
    the execution of this process, allowing them to execute arbitrary commands on the underlying
    operating system with root privileges.
    """
    # List of vulnerable versions
    vulnerable_versions = [
        '7.0.1', '7.0.2', '7.0.3', '7.1.0',  # IOS XR versions
        '2.6.5',  # Virtual Topology System versions
        '4.3.9.1', '4.4.5.6', '4.5.7', '4.6.1.7', '4.7.1', '5.1.0.1',  # Network Services Orchestrator versions
        '3.12.1',  # Enterprise NFV Infrastructure Software versions
        '18.4.4', '19.2.1',  # Catalyst SD-WAN Manager versions
        '16.10.2', '16.12.1b', '17.2.1r',  # IOS XE Catalyst SD-WAN versions
        '18.4.4', '19.2.1'  # SD-WAN vEdge Router versions
    ]

    # Extract the version information
    version_output = commands.show_version

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check ConfD process
    confd_output = commands.check_confd

    # Check if ConfD is running
    confd_running = 'confd' in confd_output

    # Assert that the device is not vulnerable
    assert not confd_running, (
        f"Device {device.name} is vulnerable to CVE-2022-20655. "
        "The device is running a vulnerable version with ConfD enabled, "
        "which could allow an authenticated attacker to execute arbitrary commands with root privileges. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cli-cmdinj-4MttWZPB"
    )
