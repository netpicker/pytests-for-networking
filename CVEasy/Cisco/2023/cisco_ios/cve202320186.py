from comfy import high


@high(
    name='rule_cve202320186',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_aaa='show running-config | include aaa|ip scp'
    ),
)
def rule_cve202320186(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20186 vulnerability in Cisco IOS Software.
    The vulnerability is due to incorrect processing of SCP commands in AAA command authorization checks.
    An attacker with valid credentials and level 15 privileges could exploit this vulnerability by using
    SCP to connect to an affected device from an external machine, potentially allowing them to obtain
    or change the configuration of the affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        '15.0(1)M', '15.1(4)M', '15.2(4)M', '15.3(3)M', '15.4(3)M', '15.5(3)M',
        '15.6(3)M', '15.7(3)M', '15.8(3)M', '15.9(3)M', '15.1(2)SG', '15.1(2)SY',
        '15.2(1)E', '15.2(2)E', '15.2(3)E', '15.2(4)E', '15.2(5)E', '15.2(6)E',
        '15.2(7)E', '15.2(8)E', '15.5(1)SY'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check AAA and SCP configuration
    aaa_output = commands.check_aaa

    # Check if AAA authorization and SCP are configured
    aaa_configured = 'aaa authorization' in aaa_output
    scp_configured = 'ip scp server enable' in aaa_output

    # Device is vulnerable if both AAA authorization and SCP are enabled
    is_vulnerable = aaa_configured and scp_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2023-20186. "
        "The device is running a vulnerable version AND has both AAA authorization and SCP enabled, "
        "which could allow an authenticated attacker to bypass command authorization. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aaascp-Tyj4fEJm"
    )
