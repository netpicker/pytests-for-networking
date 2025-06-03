from comfy import high


@high(
    name='rule_cve202320187',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include ASR1',
        check_ipv6='show running-config | include ipv6 multicast'
    ),
)
def rule_cve202320187(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20187 vulnerability in Cisco IOS XE Software for ASR 1000 Series routers.
    The vulnerability is due to incorrect handling of certain IPv6 multicast packets when they are fanned out
    more than seven times on an affected device. An attacker could exploit this vulnerability by sending
    specific IPv6 multicast or IPv6 multicast VPN (MVPNv6) packets through the affected device.
    """
    # Extract the output of the command to check platform type
    platform_output = commands.check_platform

    # Check if the device is an ASR 1000 Series router
    is_asr1000 = 'ASR1' in platform_output

    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        '3.7.1S', '3.7.2S', '3.7.3S', '3.7.4S', '3.7.5S', '3.7.6S', '3.7.7S', '3.7.2tS',
        '3.8.0S', '3.8.1S', '3.8.2S', '3.9.0S', '3.9.1S', '3.9.2S',
        '3.10.0S', '3.10.1S', '3.10.2S', '3.10.3S', '3.10.4S', '3.10.5S', '3.10.6S',
        '3.10.7S', '3.10.8S', '3.10.9S', '3.10.10S', '3.10.1xbS', '3.10.8aS',
        '3.11.0S', '3.11.1S', '3.11.2S', '3.11.3S', '3.11.4S',
        '3.12.0S', '3.12.1S', '3.12.2S', '3.12.3S', '3.12.4S',
        '3.13.0S', '3.13.1S', '3.13.2S', '3.13.3S', '3.13.4S', '3.13.5S', '3.13.2aS',
        '3.13.5aS', '3.13.6S', '3.13.7S', '3.13.6aS', '3.13.8S', '3.13.9S', '3.13.10S',
        '3.14.0S', '3.14.1S', '3.14.2S', '3.14.3S', '3.14.4S',
        '3.15.0S', '3.15.1S', '3.15.2S', '3.15.3S', '3.15.4S',
        '3.16.0S', '3.16.1aS', '3.16.2S', '3.16.3S', '3.16.2bS', '3.16.4aS', '3.16.4bS',
        '3.16.5S', '3.16.6S', '3.16.7S', '3.16.6bS', '3.16.7aS', '3.16.7bS', '3.16.8S',
        '3.16.9S', '3.16.10S',
        '3.17.0S', '3.17.1S', '3.17.2S', '3.17.1aS', '3.17.3S', '3.17.4S'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Extract the output of the command to check IPv6 multicast configuration
    ipv6_output = commands.check_ipv6

    # Check if IPv6 multicast is configured
    ipv6_multicast_configured = 'ipv6 multicast' in ipv6_output

    # Assert that the device is not vulnerable
    assert not (is_asr1000 and version_vulnerable and ipv6_multicast_configured), (
        f"Device {device.name} is vulnerable to CVE-2023-20187. "
        "The device is an ASR 1000 Series router running a vulnerable version with IPv6 multicast configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-mlre-H93FswRz"
    )
