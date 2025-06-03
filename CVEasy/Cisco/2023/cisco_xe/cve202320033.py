from comfy import high


@high(
    name='rule_cve202320033',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_mgmt='show running-config | include interface GigabitEthernet0'
    ),
)
def rule_cve202320033(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20033 vulnerability in Cisco IOS XE Software for
    Catalyst 3650/3850 Series Switches. The vulnerability is due to improper resource
    management when processing traffic received on the management interface.  
    An attacker could exploit this vulnerability by sending a high rate of traffic to 
    the management interface.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 16.3 versions
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b',
        '16.3.6', '16.3.7', '16.3.8', '16.3.9', '16.3.10', '16.3.11',
        # 16.4-16.9 versions
        '16.4.1', '16.5.1', '16.5.1a', '16.6.1', '16.6.2', '16.6.3', '16.6.4',
        '16.6.5', '16.6.4a', '16.6.6', '16.6.7', '16.6.8', '16.6.9', '16.6.10',
        '16.7.1', '16.8.1', '16.8.1a', '16.8.1s', '16.9.1', '16.9.2', '16.9.1s',
        '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.6', '16.9.7', '16.9.8',
        # 16.11-16.12 versions
        '16.11.1', '16.11.2', '16.11.1s', '16.12.1', '16.12.1s', '16.12.2',
        '16.12.3', '16.12.8', '16.12.4', '16.12.3s', '16.12.3a', '16.12.5',
        '16.12.6', '16.12.5b', '16.12.6a', '16.12.7', '16.12.9'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check management interface configuration
    mgmt_output = commands.check_mgmt

    # Check if management interface is configured
    mgmt_configured = 'interface GigabitEthernet0' in mgmt_output

    # Assert that the device is not vulnerable
    assert not mgmt_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20033. "
        "The device is running a vulnerable version AND has management interface configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat3k-dos-ZZA4Gb3r"
    )
