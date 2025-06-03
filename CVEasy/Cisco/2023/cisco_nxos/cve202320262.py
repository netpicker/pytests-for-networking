from comfy import high


@high(
    name='rule_cve202320262',
    platform=['cisco_sdwan'],
    commands=dict(
        show_version='show version',
        check_ssh='show running-config | include ssh'
    ),
)
def rule_cve202320262(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20262 vulnerability in Cisco Catalyst SD-WAN Manager.
    The vulnerability is due to insufficient resource management when an affected system is in an error condition,
    which could allow an unauthenticated, remote attacker to cause a process crash, resulting in a DoS condition
    for SSH access.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 17.2 versions
        '17.2.4', '17.2.5', '17.2.6', '17.2.7', '17.2.8', '17.2.9', '17.2.10',
        # 18.2 versions
        '18.2.0',
        # 18.3 versions
        '18.3.0', '18.3.1', '18.3.3', '18.3.3.1', '18.3.4', '18.3.5', '18.3.6', '18.3.7', '18.3.8',
        # 18.4 versions
        '18.4.0', '18.4.0.1', '18.4.1', '18.4.3', '18.4.302', '18.4.303', '18.4.4', '18.4.5', '18.4.6',
        # 19.1 versions
        '19.1.0',
        # 19.2 versions
        '19.2.0', '19.2.097', '19.2.099', '19.2.1', '19.2.2', '19.2.3', '19.2.31', '19.2.929', '19.2.4',
        # 19.3 versions
        '19.3.0',
        # 20.1 versions
        '20.1.1', '20.1.1.1', '20.1.11', '20.1.12', '20.1.2', '20.1.3', '20.1.3.1',
        # 20.3 versions
        '20.3.1', '20.3.2', '20.3.2.1', '20.3.3', '20.3.3.1', '20.3.4', '20.3.4.1', '20.3.4.2', '20.3.4.3',
        '20.3.5', '20.3.5.1', '20.3.6',
        # 20.4 versions
        '20.4.1', '20.4.1.1', '20.4.1.2', '20.4.2', '20.4.2.1', '20.4.2.2', '20.4.2.3',
        # 20.5 versions
        '20.5.1', '20.5.1.1', '20.5.1.2',
        # 20.6 versions
        '20.6.1', '20.6.1.1', '20.6.1.2', '20.6.2', '20.6.2.1', '20.6.2.2', '20.6.3', '20.6.3.1', '20.6.3.2',
        '20.6.3.3', '20.6.3.4', '20.6.4', '20.6.4.1', '20.6.4.2', '20.6.5', '20.6.5.2', '20.6.5.4', '20.6.5.5',
        # 20.7 versions
        '20.7.1', '20.7.1.1',
        # 20.8 versions
        '20.8.1',
        # 20.9 versions
        '20.9.1', '20.9.2.3',
        # 20.10 versions
        '20.10.1.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check SSH configuration
    ssh_output = commands.check_ssh

    # Check if SSH is configured
    ssh_configured = 'ssh' in ssh_output

    # Assert that the device is not vulnerable
    assert not ssh_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20262. "
        "The device is running a vulnerable version AND has SSH configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vman-sc-LRLfu2z"
    )
