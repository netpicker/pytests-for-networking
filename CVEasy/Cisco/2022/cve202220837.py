from comfy import high


@high(
    name='rule_cve202220837',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_nat='show running-config | include ip nat|alg'
    ),
)
def rule_cve202220837(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20837 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to a logic error in the DNS application layer gateway (ALG) functionality
    used by Network Address Translation (NAT). An unauthenticated, remote attacker could exploit this
    vulnerability by sending crafted IPv4 TCP DNS packets through an affected device that is performing
    NAT for DNS packets, causing the device to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check NAT and ALG configuration
    nat_output = commands.check_nat

    # Check if NAT is configured with DNS ALG
    nat_configured = 'ip nat' in nat_output
    alg_enabled = not ('no ip nat service alg dns tcp' in nat_output)  # ALG is enabled by default

    # Device is vulnerable if NAT is configured and DNS ALG is not explicitly disabled
    is_vulnerable = nat_configured and alg_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20837. "
        "The device has NAT configured with DNS ALG enabled, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted "
        "IPv4 TCP DNS packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-alg-dos-KU9Z8kFX"
    )
