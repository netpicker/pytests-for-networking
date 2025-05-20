from comfy import high


@high(
    name='rule_cve202134697',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_ddos='show running-config | include tcp syn-flood|half-open|syn-cookie'
    ),
)
def rule_cve202134697(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34697 vulnerability in Cisco IOS XE Software.
    The vulnerability in the Protection Against Distributed Denial of Service Attacks feature
    could allow an unauthenticated, remote attacker to conduct DoS attacks due to incorrect
    programming of the half-opened connections limit, TCP SYN flood limit, or TCP SYN cookie features.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for DDoS protection configuration
    ddos_config = commands.check_ddos

    # Check if any DDoS protection features are enabled
    ddos_enabled = any(feature in ddos_config for feature in [
        'tcp syn-flood',
        'half-open',
        'syn-cookie'
    ])

    # Device is vulnerable if DDoS protection features are enabled
    is_vulnerable = ddos_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34697. "
        "The device has DDoS protection features enabled (TCP SYN flood, half-open connections limit, "
        "or TCP SYN cookie), which could allow an unauthenticated remote attacker to conduct "
        "denial of service attacks through traffic flooding. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-zbfw-tguGuYq"
    )
