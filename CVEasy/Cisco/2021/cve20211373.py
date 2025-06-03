from comfy import high


@high(
    name='rule_cve20211373',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_wireless='show running-config | include wireless|ap|capwap'
    ),
)
def rule_cve20211373(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1373 vulnerability in Cisco IOS XE Wireless Controller Software.
    The vulnerability is due to insufficient validation of CAPWAP packets that could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a Catalyst 9000 Wireless Controller
    if 'C9' not in version_output:
        return

    # Check for wireless/CAPWAP configuration
    wireless_config = commands.check_wireless
    wireless_enabled = any(feature in wireless_config for feature in [
        'wireless management interface',
        'ap capwap',
        'wireless mobility controller'
    ])

    # If wireless features are enabled, device is potentially vulnerable
    assert not wireless_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1373. "
        "The device is a Catalyst 9000 Wireless Controller with wireless features enabled, "
        "which could allow an unauthenticated, remote attacker to cause a denial of service condition "
        "through malformed CAPWAP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-2OA3JgKS"
    )
