from comfy import high


@high(
    name='rule_cve202520315',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_nbar_capwap='show running-config | include tunneled-traffic capwap',
        show_nbar_state='show ip nbar control-plane | include NBAR state'
    ),
)
def rule_cve202520315(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20315 vulnerability in Cisco IOS XE Software.
    The vulnerability is in the Network-Based Application Recognition (NBAR) feature and is due to
    improper handling of malformed Control and Provisioning of Wireless Access Points (CAPWAP) packets.
    An unauthenticated, remote attacker could exploit this vulnerability by sending malformed CAPWAP
    packets through an affected device, causing it to reload unexpectedly (DoS condition).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Software (vulnerability only affects IOS XE)
    is_ios_xe = 'IOS XE Software' in version_output or 'Cisco IOS XE Software' in version_output

    # If not IOS XE, device is not vulnerable
    if not is_ios_xe:
        return

    # Check if CAPWAP inspection for NBAR is enabled
    nbar_capwap_output = commands.show_nbar_capwap
    capwap_inspection_enabled = 'ip nbar classification tunneled-traffic capwap' in nbar_capwap_output

    # If CAPWAP inspection is not enabled, device is not vulnerable
    if not capwap_inspection_enabled:
        return

    # Check if NBAR is activated
    nbar_state_output = commands.show_nbar_state
    nbar_activated = 'NBAR state is ACTIVATED' in nbar_state_output or 'NBAR state: ACTIVATED' in nbar_state_output

    # Device is vulnerable if both CAPWAP inspection for NBAR is enabled AND NBAR is activated
    is_vulnerable = capwap_inspection_enabled and nbar_activated

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20315. "
        "The device is running Cisco IOS XE Software with NBAR CAPWAP inspection enabled AND NBAR is activated, "
        "which makes it susceptible to DoS attacks via malformed CAPWAP packets. "
        "Mitigation: Disable CAPWAP inspection for NBAR using 'no ip nbar classification tunneled-traffic capwap'. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nbar-dos-LAvwTmeT"
    )