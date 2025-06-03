from comfy import high


@high(
    name='rule_cve202320067',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_wlc='show running-config | include wireless|http client'
    ),
)
def rule_cve202320067(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20067 vulnerability in Cisco IOS XE Software for Wireless LAN Controllers.
    The vulnerability is due to insufficient input validation of received traffic in the "
    "HTTP-based client profiling feature.
    An attacker could exploit this vulnerability by sending crafted traffic through a wireless access point,
    causing high CPU utilization and a denial of service condition.
    """
    # Extract the output of the command to check WLC and HTTP client profiling configuration
    wlc_output = commands.check_wlc

    # Check if WLC and HTTP client profiling are configured
    wlc_configured = 'wireless' in wlc_output and 'http client' in wlc_output

    # Assert that the device is not vulnerable
    assert not wlc_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20067. "
        "The device has wireless LAN controller and HTTP client profiling enabled, "
        "which could allow an attacker to cause a denial of service condition. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-dos-wFujBHKw"
    )
