from comfy import high


@high(
    name='rule_cve20211439',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_mdns='show running-config | include mdns|flexconnect|vlan'
    ),
)
def rule_cve20211439(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1439 vulnerability in Cisco Aironet Access Points Software.
    The vulnerability in the mDNS gateway feature could allow an unauthenticated, adjacent attacker
    to cause a denial of service (DoS) condition through malformed mDNS packets when FlexConnect
    local switching mode or mDNS VLAN is configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software for Aironet
    if 'IOS XE Software' not in version_output or 'Aironet' not in version_output:
        return

    # Check for mDNS and FlexConnect configuration
    config = commands.check_mdns

    # Check if mDNS gateway is enabled
    mdns_enabled = 'mdns gateway' in config

    # Check if FlexConnect local switching or mDNS VLAN is configured
    flexconnect_enabled = 'flexconnect local-switching' in config
    mdns_vlan_configured = any('vlan' in line and 'mdns' in line for line in config.splitlines())

    # Device is vulnerable if mDNS gateway is enabled with either FlexConnect or mDNS VLAN
    is_vulnerable = mdns_enabled and (flexconnect_enabled or mdns_vlan_configured)

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1439. "
        "The device has mDNS gateway enabled with FlexConnect local switching or mDNS VLAN configured, "
        "which could allow an unauthenticated adjacent attacker to cause a denial of service condition. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aironet-mdns-dos-E6KwYuMx"
    )
