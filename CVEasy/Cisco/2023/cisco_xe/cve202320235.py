from comfy import high


@high(
    name='rule_cve202320235',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox|app-hosting'
    ),
)
def rule_cve202320235(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20235 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient protection of the on-device application development
    workflow feature in the Cisco IOx application hosting infrastructure. An attacker could
    exploit this vulnerability by using Docker CLI to access the underlying operating system
    as the root user.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        # 17.3 versions
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x',
        '17.3.1z', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c',
        '17.3.5a', '17.3.5b', '17.3.7',
        # 17.4-17.6 versions
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a', '17.5.1b', '17.5.1c',
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.5a',
        # 17.7-17.12 versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a', '17.9.4', '17.9.1y1', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.12.1', '17.12.1a', '17.11.99SW'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check IOx configuration
    iox_output = commands.check_iox

    # Check if IOx or app-hosting is configured
    iox_configured = any(feature in iox_output for feature in ['iox', 'app-hosting'])

    # Assert that the device is not vulnerable
    assert not iox_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20235. "
        "The device is running a vulnerable version AND has IOx/app-hosting configured, "
        "which could allow an attacker to gain root access to the underlying operating system. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rdocker-uATbukKn"
    )
