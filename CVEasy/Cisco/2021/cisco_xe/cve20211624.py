from comfy import high


@high(
    name='rule_cve20211624',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_nat='show running-config | include ip nat|rate-limit'
    ),
)
def rule_cve20211624(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1624 vulnerability in Cisco IOS XE Software.
    The vulnerability in the Rate Limiting Network Address Translation (NAT) feature could allow
    an unauthenticated, remote attacker to cause high CPU utilization in the Cisco QuantumFlow
    Processor, resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for NAT and rate limiting configuration
    nat_config = commands.check_nat

    # Check if NAT is enabled
    nat_enabled = 'ip nat' in nat_config

    # Check if rate limiting is configured for NAT
    rate_limit_enabled = any(feature in nat_config for feature in [
        'rate-limit',
        'ip nat rate-limit'
    ])

    # Device is vulnerable if NAT is enabled with rate limiting
    is_vulnerable = nat_enabled and rate_limit_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1624. "
        "The device has NAT enabled with rate limiting configured, which could allow an unauthenticated "
        "remote attacker to cause high CPU utilization in the QuantumFlow Processor through high-rate traffic. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ratenat-pYVLA7wM"
    )
