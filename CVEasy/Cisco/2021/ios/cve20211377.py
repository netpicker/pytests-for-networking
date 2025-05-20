from comfy import high


@high(
    name='rule_cve20211377',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_arp='show running-config | include arp'
    ),
)
def rule_cve20211377(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1377 vulnerability in Cisco IOS and IOS XE Software.
    The vulnerability is due to insufficient ARP entry management, which could allow an
    unauthenticated, remote attacker to prevent an affected device from resolving ARP entries
    for legitimate hosts on connected subnets, resulting in a denial of service condition.

    Note: This vulnerability exists because ARP entries are mismanaged. An attacker could
    exploit this by continuously sending traffic that results in incomplete ARP entries.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS or IOS-XE
    is_ios = 'Cisco IOS Software' in version_output
    is_ios_xe = 'Cisco IOS XE Software' in version_output

    # If neither IOS nor IOS-XE, device is not vulnerable
    if not (is_ios or is_ios_xe):
        return

    # Extract ARP configuration
    arp_config = commands.check_arp

    # Check for any ARP protection mechanisms
    arp_protection = any(protection in arp_config for protection in [
        'arp inspection',
        'ip arp proxy disable',
        'arp rate-limit'
    ])

    # Device is vulnerable if it's running IOS/IOS-XE and doesn't have ARP protection
    is_vulnerable = (is_ios or is_ios_xe) and not arp_protection

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1377. "
        "The device is running IOS/IOS-XE software and lacks ARP protection mechanisms, "
        "which could allow an attacker to cause ARP resolution failures through malicious traffic. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-arp-mtfhBfjE"
    )
