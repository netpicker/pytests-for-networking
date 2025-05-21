from comfy import high


@high(
    name='rule_cve20211446',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_nat='show running-config | include ip nat|alg|dns'
    ),
)
def rule_cve20211446(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1446 vulnerability in Cisco IOS XE Software.
    The vulnerability in the DNS application layer gateway (ALG) functionality used by NAT
    could allow an unauthenticated, remote attacker to cause a denial of service (DoS)
    condition through crafted IPv4 DNS packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for NAT and DNS ALG configuration
    nat_config = commands.check_nat

    # Check if NAT is enabled
    nat_enabled = 'ip nat' in nat_config

    # Check if DNS ALG is enabled (it's enabled by default when NAT is enabled,
    # unless explicitly disabled with 'no ip nat service alg dns')
    dns_alg_disabled = 'no ip nat service alg dns' in nat_config
    dns_alg_enabled = nat_enabled and not dns_alg_disabled

    # Device is vulnerable if NAT is enabled with DNS ALG
    is_vulnerable = dns_alg_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1446. "
        "The device has NAT enabled with DNS ALG functionality, which could allow an unauthenticated "
        "remote attacker to cause a denial of service condition through crafted IPv4 DNS packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-alg-dos-hbBS7SZE"
    )
