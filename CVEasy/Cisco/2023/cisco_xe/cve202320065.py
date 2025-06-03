from comfy import high


@high(
    name='rule_cve202320065',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox'
    ),
)
def rule_cve202320065(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20065 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient restrictions on the hosted application in the
    Cisco IOx application hosting subsystem. An attacker could exploit this vulnerability
    by logging in to and then escaping the Cisco IOx application container.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 16.4 versions
        '16.4.1', '16.4.2', '16.4.3',
        # 17.3 versions
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x',
        '17.3.1z', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c',
        '17.3.5a', '17.3.5b',
        # 17.4-17.9 versions
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a', '17.5.1b', '17.5.1c',
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.2a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check IOx configuration
    iox_output = commands.check_iox

    # Check if IOx is configured
    iox_configured = 'iox' in iox_output

    # Assert that the device is not vulnerable
    assert not iox_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20065. "
        "The device is running a vulnerable version AND has IOx application hosting configured, "
        "which could allow an attacker to elevate privileges to root. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-iox-priv-escalate-Xg8zkyPk"
    )
