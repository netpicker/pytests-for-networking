from comfy import high


@high(
    name='rule_cve202320227',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_l2tp='show running-config | include vpdn|l2tp'
    ),
)
def rule_cve202320227(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20227 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper handling of certain L2TP packets. An attacker could
    exploit this vulnerability by sending crafted L2TP packets to an affected device, causing
    it to reload unexpectedly and resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        # 16.8-16.9 versions
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.1d',
        '16.8.2', '16.8.1e', '16.8.3', '16.9.1', '16.9.2', '16.9.1a',
        '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        # 16.10-16.12 versions
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1c', '16.10.1e',
        '16.10.1d', '16.10.2', '16.10.1f', '16.10.1g', '16.10.3', '16.11.1',
        '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s', '16.12.1', '16.12.1s',
        '16.12.1a', '16.12.1c', '16.12.1w', '16.12.2', '16.12.1y', '16.12.2a',
        '16.12.3', '16.12.8', '16.12.2s', '16.12.1x', '16.12.1t', '16.12.4',
        '16.12.3s', '16.12.4a', '16.12.5', '16.12.6', '16.12.1z1', '16.12.5a',
        '16.12.1z2', '16.12.6a', '16.12.7', '16.12.10a',
        # 17.1-17.5 versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3', '17.2.1', '17.2.1r',
        '17.2.1a', '17.2.1v', '17.2.2', '17.2.3', '17.3.1', '17.3.2', '17.3.3',
        '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x', '17.3.1z', '17.3.4', '17.3.5',
        '17.3.4a', '17.3.6', '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.4.1',
        '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a', '17.5.1', '17.5.1a', '17.5.1b',
        '17.5.1c'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check L2TP configuration
    l2tp_output = commands.check_l2tp

    # Check if L2TP is configured
    l2tp_configured = any(feature in l2tp_output for feature in ['vpdn', 'l2tp'])

    # Assert that the device is not vulnerable
    assert not l2tp_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20227. "
        "The device is running a vulnerable version AND has L2TP configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-l2tp-dos-eB5tuFmV"
    )
