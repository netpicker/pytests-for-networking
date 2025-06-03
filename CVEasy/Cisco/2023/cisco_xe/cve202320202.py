from comfy import high


@high(
    name='rule_cve202320202',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_wncd='show running-config | include wireless|wncd'
    ),
)
def rule_cve202320202(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20202 vulnerability in Cisco IOS XE Software for Wireless LAN Controllers.
    The vulnerability is due to improper memory management in the Wireless Network Control daemon (wncd).
    An attacker could exploit this vulnerability by sending a series of network requests to an affected device,
    causing the wncd process to consume available memory and eventually cause the device to reload.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        # 17.9 versions
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y',
        '17.9.2a', '17.9.1x1',
        # 17.10 versions
        '17.10.1', '17.10.1a', '17.10.1b'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check WNCD configuration
    wncd_output = commands.check_wncd

    # Check if wireless/WNCD is configured
    wireless_configured = 'wireless' in wncd_output and 'wncd' in wncd_output

    # Assert that the device is not vulnerable
    assert not wireless_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20202. "
        "The device is running a vulnerable version AND has wireless LAN controller with WNCD configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-wncd-HFGMsfSD"
    )
