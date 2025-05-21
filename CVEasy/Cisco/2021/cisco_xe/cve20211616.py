from comfy import high


@high(
    name='rule_cve20211616',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_nat='show running-config | include ip nat|alg|h323'
    ),
)
def rule_cve20211616(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1616 vulnerability in Cisco IOS XE Software.
    The vulnerability in the H.323 application level gateway (ALG) used by NAT could allow
    an unauthenticated, remote attacker to bypass the ALG through insufficient data validation
    of traffic traversing the ALG.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for NAT and H.323 ALG configuration
    nat_config = commands.check_nat

    # Check if NAT is enabled
    nat_enabled = 'ip nat' in nat_config

    # Check if H.323 ALG is enabled (it's enabled by default when NAT is enabled,
    # unless explicitly disabled with 'no ip nat service alg h323')
    h323_alg_disabled = 'no ip nat service alg h323' in nat_config
    h323_alg_enabled = nat_enabled and not h323_alg_disabled

    # Device is vulnerable if NAT is enabled with H.323 ALG
    is_vulnerable = h323_alg_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1616. "
        "The device has NAT enabled with H.323 ALG functionality, which could allow an unauthenticated "
        "remote attacker to bypass the ALG through crafted traffic (NAT Slipstreaming). "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-h323alg-bypass-4vy2MP2Q"
    )
